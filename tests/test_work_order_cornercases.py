# Copyright 2019 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import sys
import time
import argparse
import random
import json
from builtins import bytes

from service_client.generic import GenericServiceClient
import crypto.crypto as crypto
import utility.signature as signature
import worker.worker as worker
from shared_kv.shared_kv_interface import KvStorage
import logging
import utility.tcf_helper as enclave_helper
logger = logging.getLogger(__name__)

# this will be used to test transaction dependencies
txn_dependencies = []

# representation of the enclave
enclave = None

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def LocalMain(config) :

    if config.get('KvStorage') is None:
        logger.error("Kv Storage path is missing")
        sys.exit(-1)

    KvHelper = KvStorage()
    KvHelper.open((TCFHOME + '/' + config['KvStorage']['StoragePath']))

    if not input_json_str and not input_json_dir:
       logger.error("JSON input file is not provided")
       exit(1)

    if not output_json_file_name:
        logger.error("JSON output file is not provided")
        exit(1)
    
    if not server_uri:
        logger.error("Server URI is not provided")
        exit(1)
        
    logger.info('Execute work order')
    uri_client = GenericServiceClient(server_uri) 
    response = None
    if input_json_dir:
        directory = os.fsencode(input_json_dir)
        files = os.listdir(directory)
            
        for file in sorted(files) :
            input_json_str1 = enclave_helper.read_json_file((directory.decode("utf-8") + file.decode("utf-8")))

            #----------------------------------------------------------------------------------

            #If Client request is WorkOrderSubmit,a requester payload’s signature with the requester private signing key is generated.
            if "WorkOrderSubmit" in input_json_str1 :
                input_json_str1 = signature_generate(input_json_str1)
                if input_json_str1 is None:
                    continue
            #----------------------------------------------------------------------------------

            # Update the worker ID
            if response:
                if "workerId" in input_json_str1 :
                   #Retrieving the worker id from the "WorkerRetrieve" response and update the worker id information for further json requests
                   if 'result' in response and 'ids' in response["result"].keys():
                       input_json_final = json.loads(input_json_str1)
                       input_json_final['params']['workerId'] = response['result']['ids'][0]
                       input_json_str1 = json.dumps(input_json_final)
                       logger.info("**********Worker details Updated with Worker ID*********\n%s\n", response['result']['ids'][0])
            #-----------------------------------------------------------------------------------

            logger.info("*********Request Json********* \n%s\n", input_json_str1)
            response = uri_client._postmsg(input_json_str1)
            logger.info("**********Received Response*********\n%s\n", response)

            #-----------------------------------------------------------------------------------

            #Worker details are loaded into Worker_Obj
            if "WorkerRetrieve" in input_json_str1 :
                    worker_obj.load_worker(response)
            #----------------------------------------------------------------------------------
            
            # Key already exist test scenario "test_wo_submit_key_already_exist"
            response = uri_client._postmsg(input_json_str1)
            if 'WorkOrderSubmit' in input_json_str1 and 'result' not in response:
                logger.info("*****key already exist *****")
                assert response['error']['message'], 'key already exist'
                assert response['error']['code'], 8
            #----------------------------------------------------------------------------------

            # Polling for the "WorkOrderGetResult" and break when you get the result
            while('WorkOrderGetResult' in input_json_str1 and 'result' not in response):
                response = uri_client._postmsg(input_json_str1)
                logger.info(" Received Response : %s, \n \n ", response)
                time.sleep(3)
            #----------------------------------------------------------------------------------

            #Verify the signature
            if ( 'WorkOrderGetResult' in input_json_str1 ):
                sig_bool = verify_signature(json.dumps(response))
            #----------------------------------------------------------------------------------
    else :
        logger.info('Input Request %s', input_json_str)
        input_json_str_1 = signature_generate(input_json_str)
        response = uri_client._postmsg(input_json_str_1)
        logger.info("Received Response : %s , \n \n ", response);
        sig_bool = verify_signature(json.dumps(response))


    exit(0)

TCFHOME = os.environ.get("TCF_HOME", "../../")

# -----------------------------------------------------------------
def ParseCommandLine(config, args) :
    logger.info('***************** INTEL TRUSTED COMPUTE FRAMEWORK (TCF)*****************') 
    global input_json_str
    global input_json_dir
    global server_uri
    global output_json_file_name
    global consensus_file_name
    global sig_obj
    global worker_obj
    global private_key

    parser = argparse.ArgumentParser()
    parser.add_argument('--logfile', help='Name of the log file, __screen__ for standard output', type=str)
    parser.add_argument('-p', '--private_key',help="Private Key of the Client", type=str, default=None)
    parser.add_argument('--loglevel', help='Logging level', type=str)
    parser.add_argument('-i', '--input_file', help='JSON input file name', type=str, default='input.json')
    parser.add_argument('--input_dir', help='Logging level', type=str, default=[])
    parser.add_argument(
        '-c', '--connect_uri', help='URI to send requests to', type=str, default=[])
    parser.add_argument(
        'output_file',
        help='JSON output file name',
        type=str,
        default='output.json',
        nargs='?')

    options = parser.parse_args(args)

    if config.get('Logging') is None :
        config['Logging'] = {
            'LogFile' : '__screen__',
            'LogLevel' : 'INFO'
        }
    if options.logfile :
        config['Logging']['LogFile'] = options.logfile
    if options.loglevel :
        config['Logging']['LogLevel'] = options.loglevel.upper()

    input_json_str = None
    input_json_dir = None

    if options.connect_uri:
        server_uri = options.connect_uri
    else:
        logger.error("ERROR: Please enter the server URI")

    if options.input_dir:
        logger.info('Load Json Directory from %s',options.input_dir)
        input_json_dir = options.input_dir
    elif options.input_file:
        try:
            logger.info('load JSON input from %s', options.input_file)
            with open(options.input_file, "r") as file:
                input_json_str = file.read()
        except:
            logger.error("ERROR: Failed to read from file %s", options.input_file)
    else :
        logger.info('No input found')

    if options.output_file:
        output_json_file_name = options.output_file
    else:
        output_json_file_name = None

    if options.private_key:
        private_key = options.private_key
    else:#Generating the private Key for the client
        private_key = generate_signing_keys()

    # Initializing Signature object, Worker Object
    sig_obj = signature.ClientSignature()
    worker_obj = worker.Worker()

#-----------------------------------------------------------------------------------------------
def generate_signing_keys():
    signing_key = crypto.SIG_PrivateKey()
    signing_key.Generate()
    return signing_key

# -----------------------------------------------------------------
def signature_generate(json_input_str):
    logger.info("**************Signature Generation Started*************")
    request_json = sig_obj.sign_request(json_input_str,worker_obj,private_key)
    logger.debug("---------------------------------------------------request_json: %s", request_json)
    return request_json

# -----------------------------------------------------------------
def verify_signature(json_response_str):
    logger.info("***********Signature Verification Started ...**********")
    input_json = json.loads(json_response_str)
    result = sig_obj.verify_signature(input_json,worker_obj)
    try:
        if result > 0:
            logger.info('Signature Verified')
        else :
            logger.info('Signature Failed')
    except:
            logger.error("ERROR: Failed to analyze Signature Verification")
    return result

    # -----------------------------------------------------------------
def Main(args=None):
    import config.config as pconfig
    import utility.logger as plogger

    # parse out the configuration file first
    conffiles = [ 'work_order_tests.toml' ]
    confpaths = [ ".", TCFHOME + "/" + "config", "../../etc"]

    parser = argparse.ArgumentParser()
    parser.add_argument('--config', help='configuration file', nargs = '+')
    parser.add_argument('--config-dir', help='configuration folder', nargs = '+')
    (options, remainder) = parser.parse_known_args(args)

    if options.config :
        conffiles = options.config

    if options.config_dir :
        confpaths = options.config_dir

    try :
        config = pconfig.parse_configuration_files(conffiles, confpaths)
        config_json_str = json.dumps(config, indent=4)
    except pconfig.ConfigurationException as e :
        logger.error(str(e))
        sys.exit(-1)

    plogger.setup_loggers(config.get('Logging', {}))
    sys.stdout = plogger.stream_to_logger(logging.getLogger('STDOUT'), logging.DEBUG)
    sys.stderr = plogger.stream_to_logger(logging.getLogger('STDERR'), logging.WARN)

    ParseCommandLine(config, remainder)
    LocalMain(config)

#------------------------------------------------------------------------------
Main()
