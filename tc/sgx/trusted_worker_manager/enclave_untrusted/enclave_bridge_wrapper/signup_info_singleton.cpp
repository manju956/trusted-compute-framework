/* Copyright 2020 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "signup_singleton.h"
#include "signup_info_singleton.h"

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
SignupInfoSingleton::SignupInfoSingleton(
    const std::string& serialized_signup_info) :
    serialized_(serialized_signup_info) {

    // call base class implementation
    SignupInfo signup_info;
    tcf_err_t result = signup_info.DeserializeSignupInfo(
        serialized_signup_info);
    ThrowTCFError(result);
}  // SignupInfoSingleton

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
SignupInfoSingleton* deserialize_signup_info(
    const std::string&  serialized_signup_info) {
    return new SignupInfoSingleton(serialized_signup_info);
}  // deserialize_signup_info

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
std::map<std::string, std::string> CreateEnclaveData() {
    tcf_err_t presult;
    // Create some buffers for receiving the output parameters
    // CreateEnclaveData will resize appropriately
    StringArray public_enclave_data(0);
    Base64EncodedString sealed_enclave_data;
    Base64EncodedString enclave_quote;

    SignupDataSingleton signup_data;
    // Create the signup data
    presult = signup_data.CreateEnclaveData(
        public_enclave_data, sealed_enclave_data, enclave_quote);
    ThrowTCFError(presult);

    // Parse the json and save the verifying and encryption keys
    std::string verifying_key;
    std::string encryption_key;
    std::string encryption_key_signature;

    presult = SignupInfo::DeserializePublicEnclaveData(
        public_enclave_data.str(),
        verifying_key,
        encryption_key,
        encryption_key_signature);
    ThrowTCFError(presult);

    // Save the information
    std::map<std::string, std::string> result;
    result["verifying_key"] = verifying_key;
    result["encryption_key"] = encryption_key;
    result["encryption_key_signature"] = encryption_key_signature;
    result["sealed_enclave_data"] = sealed_enclave_data;
    result["enclave_quote"] = enclave_quote;

    return result;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
std::map<std::string, std::string> UnsealEnclaveData() {
    tcf_err_t presult;
    // UnsealEnclaveData will resize appropriately
    StringArray public_enclave_data(0);

    SignupDataSingleton signup_data;
    presult = signup_data.UnsealEnclaveData(
        public_enclave_data);
    ThrowTCFError(presult);

    // Parse the json and save the verifying and encryption keys
    std::string verifying_key;
    std::string encryption_key;
    std::string encryption_key_signature;

    presult = SignupInfo::DeserializePublicEnclaveData(
        public_enclave_data.str(),
        verifying_key,
        encryption_key,
        encryption_key_signature);
    ThrowTCFError(presult);

    std::map<std::string, std::string> result;
    result["verifying_key"] = verifying_key;
    result["encryption_key"] = encryption_key;
    result["encryption_key_signature"] = encryption_key_signature;

    return result;
}  // UnsealEnclaveData

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
size_t VerifyEnclaveInfo(const std::string& enclave_info,
    const std::string& mr_enclave) {

    SignupDataSingleton signup_data;
    tcf_err_t result = signup_data.VerifyEnclaveInfo(
        enclave_info, mr_enclave);
    size_t verify_status = result;
    return verify_status;
}  // VerifyEnclaveInfo
