/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2019, Magnus Edenhill
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * Example of utilizing the Windows Certificate store with sSL.
 */

#include <iostream>
#include <string>
#include <cstdlib>
#include <cstdio>
#include <csignal>
#include <cstring>
#include <sstream>

#include "../win32/wingetopt.h"
#include <windows.h>
#include <wincrypt.h>

/*
 * Typically include path in a real application would be
 * #include <librdkafka/rdkafkacpp.h>
 */
#include "rdkafkacpp.h"


/**
 * @brief Print the brokers in the cluster.
 */
static void print_brokers (const RdKafka::Handle *handle,
                           const RdKafka::Metadata *md) {
  std::cout << md->brokers()->size() << " broker(s) in cluster " <<
    handle->clusterid() << std::endl;

  /* Iterate brokers */
  RdKafka::Metadata::BrokerMetadataIterator ib;
  for (ib = md->brokers()->begin(); ib != md->brokers()->end(); ++ib)
    std::cout << "  broker " << (*ib)->id() << " at "
              << (*ib)->host() << ":" << (*ib)->port() << std::endl;

}


class ExampleSSLRetrieveCb : public RdKafka::SslCertificateRetrieveCb {
 public:
  ExampleSSLRetrieveCb (std::string const &subject, std::string const &pass)
         : m_cert_subject(subject), m_cert_store(NULL),
           m_cert_ctx(NULL), m_password(pass) {}

  ~ExampleSSLRetrieveCb() {
      if (m_cert_ctx)
        CertFreeCertificateContext(m_cert_ctx);

      if (m_cert_store)
        CertCloseStore(m_cert_store, 0);
  }

  ssize_t ssl_cert_retrieve_cb (Type type, char **buffer,
                                std::string &errstr) {

    if (!load_certificate(errstr))
      return -1;

    switch (type) {
    case CERTIFICATE_PUBLIC_KEY:
      *buffer = (char *)m_cert_ctx->pbCertEncoded;
      return m_cert_ctx->cbCertEncoded;

          case CERTIFICATE_PRIVATE_KEY:
          {
              ssize_t ret = 0;
#ifdef _MSC_VER
              /*
               * In order to export the private key the certificate 
               * must first be marked as exportable.
               *
               * Steps to export the certificate
               * 1) Create an in-memory cert store
               * 2) Add the certificate to the store
               * 3) Export the private key from the in-memory store
               */

              /*Create an in-memory cert store*/
              HCERTSTORE hMemStore = CertOpenStore(CERT_STORE_PROV_MEMORY,
                  0,
                  NULL,
                  0,
                  NULL);
              if (!hMemStore) {
                  errstr = GetErrorMsg(GetLastError());
              } else {
                  /*Add certificate to store*/
                  if (!CertAddCertificateContextToStore(hMemStore,
                      m_cert_ctx,
                      CERT_STORE_ADD_USE_EXISTING,
                      NULL)) {
                      errstr = GetErrorMsg(GetLastError());
                  } else {
                      /*Export private key from cert*/
                      CRYPT_DATA_BLOB db = { NULL };

                      if (!PFXExportCertStoreEx(hMemStore,
                          &db,
                          std::wstring(m_password.begin(), m_password.end()).c_str(), /*should probally do a better std::string to std::wstring conversion*/
                          NULL,
                          EXPORT_PRIVATE_KEYS | REPORT_NO_PRIVATE_KEY | REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY)) {
                          errstr = GetErrorMsg(GetLastError());
                      } else {
                          m_buffer.resize(db.cbData);
                          db.pbData = &m_buffer[0];

                          if (!PFXExportCertStoreEx(hMemStore,
                              &db,
                              std::wstring(m_password.begin(), m_password.end()).c_str(), /*should probally do a better std::string to std::wstring conversion*/
                              NULL,
                              EXPORT_PRIVATE_KEYS | REPORT_NO_PRIVATE_KEY | REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY)) {
                              errstr = GetErrorMsg(GetLastError());
                          } else {
                              m_buffer.resize(db.cbData);
                              *buffer = (char*)&m_buffer[0];

                              ret = m_buffer.size();
                          }
                      }
                  }
                  CertCloseStore(hMemStore, 0);
                  return ret;
              }
#else
              *buffer = NULL;
              return 0;
#endif
          }

          break;

          case CERTIFICATE_PRIVATE_KEY_PASS:
              *buffer = const_cast<char*>(m_password.c_str());
              return m_password.length();
          }
      }

      *buffer = NULL;
      return 0;
  }

 private:
     bool load_certificate(std::string& errstr) {

         if (!m_cert_ctx) {
             if (!m_cert_store) {
#ifdef _MSC_VER
                 m_cert_store = CertOpenStore(CERT_STORE_PROV_SYSTEM,
                     0,
                     NULL,
                     CERT_SYSTEM_STORE_CURRENT_USER,
                     L"My");
#endif
                 if (!m_cert_store) {
#ifdef _MSC_VER
                     errstr = GetErrorMsg(GetLastError());
#else
                     errstr = "not supported";
#endif
                     return false;
                 }
             }
#ifdef _MSC_VER
             m_cert_ctx = CertFindCertificateInStore(m_cert_store,
                 X509_ASN_ENCODING,
                 0,
                 CERT_FIND_SUBJECT_STR,
                 std::wstring(m_cert_subject.begin(), m_cert_subject.end()).c_str(), /*should probally do a better std::string to std::wstring conversion*/
                 NULL);
#endif
             if (!m_cert_ctx) {
#ifdef _MSC_VER
                 errstr = GetErrorMsg(GetLastError());
#else
                 errstr = "not supported";
#endif
                 return  false;
             }
         }

         return true;
     }

     std::string GetErrorMsg(unsigned long error)
     {
         char* message = NULL;
#ifdef _MSC_VER
         size_t ret = FormatMessageA(
             FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
             nullptr,
             error,
             0,
             (char*)&message,
             0,
             nullptr);
#else
         size_t ret = 0;
#endif
         if (ret == 0)
         {
             std::stringstream ss;

             ss << std::string("could not format message for ") << error;
             return ss.str();
         }
         else {
             std::string result(message, ret);
#ifdef _MSC_VER
             LocalFree(message);
#endif
             return result;
         }
     }

 private:
  std::string m_cert_subject;
  std::vector<uint8_t> m_buffer;
  std::string m_password;
#ifdef _MSC_VER
  PCCERT_CONTEXT m_cert_ctx;
  HCERTSTORE m_cert_store;
#else
  void *m_cert_ctx;
  void *m_cert_store;
#endif
};

class ExampleSSLVerifyCb : public RdKafka::SslCertificateVerifyCb {
 public:
  bool ssl_cert_verify_cb(char *cert, size_t len, std::string &errstr) {

#ifdef _MSC_VER
      PCCERT_CONTEXT ctx = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
          (uint8_t*)cert, static_cast<unsigned long>(len));
#else
      void* ctx = NULL;
#endif
      if (ctx) {
          /*Verify that the broker certificate is valid.  Specific application buisness logic will need to do this*/
#ifdef _MSC_VER
          CertFreeCertificateContext(ctx);
#endif
          return true;
      }

      return false;
  }
};


/* Use of this partitioner is pretty pointless since no key is provided
 * in the produce() call. */
class MyHashPartitionerCb : public RdKafka::PartitionerCb {
 public:
  int32_t partitioner_cb (const RdKafka::Topic *topic, const std::string *key,
                          int32_t partition_cnt, void *msg_opaque) {
    return djb_hash(key->c_str(), key->size()) % partition_cnt;
  }
 private:

  static inline unsigned int djb_hash (const char *str, size_t len) {
    unsigned int hash = 5381;
    for (size_t i = 0 ; i < len ; i++)
      hash = ((hash << 5) + hash) + str[i];
    return hash;
  }
};

void msg_consume(RdKafka::Message* message, void* opaque) {
  switch (message->err()) {
    case RdKafka::ERR__TIMED_OUT:
      break;

    case RdKafka::ERR_NO_ERROR:
      /* Real message */
      std::cout << "Read msg at offset " << message->offset() << std::endl;
      if (message->key()) {
        std::cout << "Key: " << *message->key() << std::endl;
      }
      printf("%.*s\n",
        static_cast<int>(message->len()),
        static_cast<const char *>(message->payload()));
      break;

    case RdKafka::ERR__PARTITION_EOF:
      /* Last message */
      if (exit_eof) {
        run = false;
      }
      break;

    case RdKafka::ERR__UNKNOWN_TOPIC:
    case RdKafka::ERR__UNKNOWN_PARTITION:
      std::cerr << "Consume failed: " << message->errstr() << std::endl;
      run = false;
      break;

    default:
      /* Errors */
      std::cerr << "Consume failed: " << message->errstr() << std::endl;
      run = false;
  }
}


class ExampleConsumeCb : public RdKafka::ConsumeCb {
 public:
  void consume_cb (RdKafka::Message &msg, void *opaque) {
    msg_consume(&msg, opaque);
  }
};



int main (int argc, char **argv) {
  std::string brokers = "localhost";
  std::string errstr;
  std::string topic_str;
  std::string mode;
  std::string debug;
  std::string cert_subject;
  std::string priv_key_pass;
  int32_t partition = RdKafka::Topic::PARTITION_UA;
  int64_t start_offset = RdKafka::Topic::OFFSET_BEGINNING;
  bool do_conf_dump = false;
  int opt;
  MyHashPartitionerCb hash_partitioner;
  int use_ccb = 0;
  int use_ssl = 0;

  /*
   * Create configuration objects
   */
  RdKafka::Conf *conf = RdKafka::Conf::create(RdKafka::Conf::CONF_GLOBAL);
  RdKafka::Conf *tconf = RdKafka::Conf::create(RdKafka::Conf::CONF_TOPIC);


  while ((opt = getopt(argc, argv, "PCLt:p:b:s:k:z:qd:o:eX:AM:f:")) != -1) {
    switch (opt) {
    case 'P':
    case 'C':
    case 'L':
      mode = opt;
      break;
    case 't':
      topic_str = optarg;
      break;
    case 'p':
      if (!strcmp(optarg, "random"))
        /* default */;
      else if (!strcmp(optarg, "hash")) {
        if (tconf->set("partitioner_cb", &hash_partitioner, errstr) !=
            RdKafka::Conf::CONF_OK) {
          std::cerr << errstr << std::endl;
          exit(1);
        }
      } else
        partition = std::atoi(optarg);
      break;
    case 'b':
      brokers = optarg;
      break;
    case 'z':
      if (conf->set("compression.codec", optarg, errstr) !=
	  RdKafka::Conf::CONF_OK) {
	std::cerr << errstr << std::endl;
	exit(1);
      }
      break;
    case 'o':
      if (!strcmp(optarg, "end"))
	start_offset = RdKafka::Topic::OFFSET_END;
      else if (!strcmp(optarg, "beginning"))
	start_offset = RdKafka::Topic::OFFSET_BEGINNING;
      else if (!strcmp(optarg, "stored"))
	start_offset = RdKafka::Topic::OFFSET_STORED;
      else
	start_offset = strtoll(optarg, NULL, 10);
      break;
    case 'e':
      exit_eof = true;
      break;
    case 'd':
      debug = optarg;
      break;
    case 'M':
      if (conf->set("statistics.interval.ms", optarg, errstr) !=
          RdKafka::Conf::CONF_OK) {
        std::cerr << errstr << std::endl;
        exit(1);
      }
      break;
    case 'X':
      {
	char *name, *val;

	if (!strcmp(optarg, "dump")) {
	  do_conf_dump = true;
	  continue;
	}

	name = optarg;
	if (!(val = strchr(name, '='))) {
          std::cerr << "%% Expected -X property=value, not " <<
              name << std::endl;
	  exit(1);
	}

	*val = '\0';
	val++;

	/* Try "topic." prefixed properties on topic
	 * conf first, and then fall through to global if
	 * it didnt match a topic configuration property. */
        RdKafka::Conf::ConfResult res;
	if (!strncmp(name, "topic.", strlen("topic.")))
          res = tconf->set(name+strlen("topic."), val, errstr);
        else
	  res = conf->set(name, val, errstr);

	if (res != RdKafka::Conf::CONF_OK) {
          std::cerr << errstr << std::endl;
	  exit(1);
	}
      }
      break;

      case 'f':
        if (!strcmp(optarg, "ccb"))
          use_ccb = 1;
        else {
          std::cerr << "Unknown option: " << optarg << std::endl;
          exit(1);
        }
        break;

      case 's':
      {
          use_ssl = 1;
          cert_subject = optarg;

          if (cert_subject.empty()) {
              std::cerr << "Invalid certificate: " << optarg << std::endl;
              exit(1);
          }

          if (conf->set("security.protocol", "ssl", errstr) != RdKafka::Conf::CONF_OK) {
              std::cerr << errstr << std::endl;
              exit(1);
          }
          break;
      }
      
      case 'k':
          priv_key_pass = optarg;
          break;

    default:
      goto usage;
    }
  }

  if (mode.empty() || (topic_str.empty() && mode != "L") || (priv_key_pass.empty() && use_ssl) || optind != argc) {
  usage:
	  std::string features;
	  conf->get("builtin.features", features);
    fprintf(stderr,
            "Usage: %s [-C|-P] -t <topic> "
            "[-p <partition>] [-b <host1:port1,host2:port2,..>]\n"
            "\n"
            "librdkafka version %s (0x%08x, builtin.features \"%s\")\n"
            "\n"
            " Options:\n"
            "  -C | -P         Consumer or Producer mode\n"
            "  -L              Metadata list mode\n"
            "  -t <topic>      Topic to fetch / produce\n"
            "  -p <num>        Partition (random partitioner)\n"
            "  -p <func>       Use partitioner:\n"
            "                  random (default), hash\n"
            "  -b <brokers>    Broker address (localhost:9092)\n"
            "  -s <cert>       The subject name of the SSL certificate to use\n"
            "  -k <pass>       The private key password if -s is specified\n"
            "  -z <codec>      Enable compression:\n"
            "                  none|gzip|snappy\n"
            "  -o <offset>     Start offset (consumer)\n"
            "  -e              Exit consumer when last message\n"
            "                  in partition has been received.\n"
            "  -d [facs..]     Enable debugging contexts:\n"
            "                  %s\n"
            "  -M <intervalms> Enable statistics\n"
            "  -X <prop=name>  Set arbitrary librdkafka "
            "configuration property\n"
            "                  Properties prefixed with \"topic.\" "
            "will be set on topic object.\n"
            "                  Use '-X list' to see the full list\n"
            "                  of supported properties.\n"
            "  -f <flag>       Set option:\n"
            "                     ccb - use consume_callback\n"
            "\n"
            " In Consumer mode:\n"
            "  writes fetched messages to stdout\n"
            " In Producer mode:\n"
            "  reads messages from stdin and sends to broker\n"
            "\n"
            "\n"
            "\n",
	    argv[0],
	    RdKafka::version_str().c_str(), RdKafka::version(),
		features.c_str(),
	    RdKafka::get_debug_contexts().c_str());
	exit(1);
  }


  /*
   * Set configuration properties
   */
  conf->set("metadata.broker.list", brokers, errstr);

  if (!debug.empty()) {
    if (conf->set("debug", debug, errstr) != RdKafka::Conf::CONF_OK) {
      std::cerr << errstr << std::endl;
      exit(1);
    }
  }

  ExampleEventCb ex_event_cb;
  conf->set("event_cb", &ex_event_cb, errstr);

  ExampleSSLRetrieveCb ssl_retrieve_cb(cert_subject, priv_key_pass);
  ExampleSSLVerifyCb ssl_verify_cb;
  
  if (use_ssl) {
      if (conf->set("ssl_cert_verify_cb", &ssl_verify_cb, errstr) != RdKafka::Conf::CONF_OK) {
          std::cerr << errstr << std::endl;
          exit(1);
      }
      if (conf->set("ssl_cert_retrieve_cb", &ssl_retrieve_cb, errstr) != RdKafka::Conf::CONF_OK) {
          std::cerr << errstr << std::endl;
          exit(1);
      }
  }

  if (do_conf_dump) {
    int pass;

    for (pass = 0 ; pass < 2 ; pass++) {
      std::list<std::string> *dump;
      if (pass == 0) {
        dump = conf->dump();
        std::cout << "# Global config" << std::endl;
      } else {
        dump = tconf->dump();
        std::cout << "# Topic config" << std::endl;
      }

      for (std::list<std::string>::iterator it = dump->begin();
           it != dump->end(); ) {
        std::cout << *it << " = ";
        it++;
        std::cout << *it << std::endl;
        it++;
      }
      std::cout << std::endl;
    }
    exit(0);
  }

  signal(SIGINT, sigterm);
  signal(SIGTERM, sigterm);


  if (mode == "P") {
    /*
     * Producer mode
     */

    if(topic_str.empty())
      goto usage;

    ExampleDeliveryReportCb ex_dr_cb;

    /* Set delivery report callback */
    conf->set("dr_cb", &ex_dr_cb, errstr);

    /*
     * Create producer using accumulated global configuration.
     */
    RdKafka::Producer *producer = RdKafka::Producer::create(conf, errstr);
    if (!producer) {
      std::cerr << "Failed to create producer: " << errstr << std::endl;
      exit(1);
    }

    std::cout << "% Created producer " << producer->name() << std::endl;

    /*
     * Create topic handle.
     */
    RdKafka::Topic *topic = RdKafka::Topic::create(producer, topic_str,
						   tconf, errstr);
    if (!topic) {
      std::cerr << "Failed to create topic: " << errstr << std::endl;
      exit(1);
    }

    /*
     * Read messages from stdin and produce to broker.
     */
    for (std::string line; run && std::getline(std::cin, line);) {
      if (line.empty()) {
        producer->poll(0);
	continue;
      }

      /*
       * Produce message
       */
      RdKafka::ErrorCode resp =
	producer->produce(topic, partition,
			  RdKafka::Producer::RK_MSG_COPY /* Copy payload */,
			  const_cast<char *>(line.c_str()), line.size(),
			  NULL, NULL);
      if (resp != RdKafka::ERR_NO_ERROR)
	std::cerr << "% Produce failed: " <<
	  RdKafka::err2str(resp) << std::endl;
      else
	std::cerr << "% Produced message (" << line.size() << " bytes)" <<
	  std::endl;

      producer->poll(0);
    }
    run = true;

    while (run && producer->outq_len() > 0) {
      std::cerr << "Waiting for " << producer->outq_len() << std::endl;
      producer->poll(1000);
    }

    delete topic;
    delete producer;


  } else if (mode == "C") {
    /*
     * Consumer mode
     */

    if(topic_str.empty())
      goto usage;

    /*
     * Create consumer using accumulated global configuration.
     */
    RdKafka::Consumer *consumer = RdKafka::Consumer::create(conf, errstr);
    if (!consumer) {
      std::cerr << "Failed to create consumer: " << errstr << std::endl;
      exit(1);
    }

    std::cout << "% Created consumer " << consumer->name() << std::endl;

    /*
     * Create topic handle.
     */
    RdKafka::Topic *topic = RdKafka::Topic::create(consumer, topic_str,
						   tconf, errstr);
    if (!topic) {
      std::cerr << "Failed to create topic: " << errstr << std::endl;
      exit(1);
    }

    /*
     * Start consumer for topic+partition at start offset
     */
    RdKafka::ErrorCode resp = consumer->start(topic, partition, start_offset);
    if (resp != RdKafka::ERR_NO_ERROR) {
      std::cerr << "Failed to start consumer: " <<
	RdKafka::err2str(resp) << std::endl;
      exit(1);
    }

    ExampleConsumeCb ex_consume_cb;

    /*
     * Consume messages
     */
    while (run) {
      if (use_ccb) {
        consumer->consume_callback(topic, partition, 1000,
                                   &ex_consume_cb, &use_ccb);
      } else {
        RdKafka::Message *msg = consumer->consume(topic, partition, 1000);
        msg_consume(msg, NULL);
        delete msg;
      }
      consumer->poll(0);
    }

    /*
     * Stop consumer
     */
    consumer->stop(topic, partition);

    consumer->poll(1000);

    delete topic;
    delete consumer;
  } else {
    /* Metadata mode */

    /*
     * Create producer using accumulated global configuration.
     */
    RdKafka::Producer *producer = RdKafka::Producer::create(conf, errstr);
    if (!producer) {
      std::cerr << "Failed to create producer: " << errstr << std::endl;
      exit(1);
    }

    std::cout << "% Created producer " << producer->name() << std::endl;

    /*
     * Create topic handle.
     */
    RdKafka::Topic *topic = NULL;
    if(!topic_str.empty()) {
      topic = RdKafka::Topic::create(producer, topic_str, tconf, errstr);
      if (!topic) {
        std::cerr << "Failed to create topic: " << errstr << std::endl;
        exit(1);
      }
    }

    while (run) {
      class RdKafka::Metadata *metadata;

      /* Fetch metadata */
      RdKafka::ErrorCode err = producer->metadata(topic!=NULL, topic,
                              &metadata, 5000);
      if (err != RdKafka::ERR_NO_ERROR) {
        std::cerr << "%% Failed to acquire metadata: " 
                  << RdKafka::err2str(err) << std::endl;
              run = 0;
              break;
      }

      metadata_print(topic_str, metadata);

      delete metadata;
      run = 0;
    }

  }

  return 0;
}
