//
// Created by viktor on 24.02.23.
//
#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"
#include <rapidjson/istreamwrapper.h>
#include <iostream>
#include <sstream>
#include "WLoger/Include/WLoger.h"

#ifndef JSON_READ_WRITE_JSON_WORKER_H
#define JSON_READ_WRITE_JSON_WORKER_H

using Json = std::shared_ptr<rapidjson::Document>;

class JsonWorker
{
public:

    /** create empty JSON object */
    static Json CreateJsonObject();

    /** add string value to JSON object */
    template <typename T>
    static void AddToJsonVal(Json& jsonObj, std::string key, const T& value)
    {
        rapidjson::Value jsonKey;
        jsonKey.SetString(key.c_str(), static_cast<rapidjson::SizeType>(key.length()), jsonObj->GetAllocator());

        rapidjson::Value jsonValue;
        std::stringstream sstr;
        sstr << value;
        std::string valueStr = sstr.str();
        jsonValue.SetString(valueStr.c_str(), static_cast<rapidjson::SizeType>(valueStr.length()), jsonObj->GetAllocator());

        jsonObj->AddMember(jsonKey, jsonValue, jsonObj->GetAllocator());
    }

    /** find and return string value from JSON object */
    static std::string FindStringVal(const Json& _jsonObj, std::string _curKey);
    /** change value from key in JSON object */
    static void ChangeVal(const Json& _jsonObj, std::string _curKey, std::string _newVal);

    /** serialize JSON object to string */
    static std::string Serialize(const Json& _jsonObj);
    /** deserialize string to JSON object */
    static Json Deserialize(const std::string& _serData);

    static void print_json(Json msgJson, std::string header)
    {
        if (msgJson->IsObject() && !msgJson->HasParseError()) {
            std::string str = "\n";
            str += (header.size() > 0 ? header + ": {" : "{");

            for (rapidjson::Value::ConstMemberIterator itr = msgJson->MemberBegin();
                itr != msgJson->MemberEnd(); ++itr){
                if(itr != msgJson->MemberBegin())
                    str += ",\n\t";
                else
                    str += "\n\t";
                std::string val = itr->value.GetString();
                const int max_len = 120;
                if(val.size() > max_len){
                    val = val.substr(0, max_len - 3);
                    val += "...";
                }
                str += std::string(itr->name.GetString()) + ": \"" + val + "\"";
            }

            WLI << str + "\n}";
        }
    }

    static Json ReadFromFile(const std::string &filename);

    static void SaveToFile(const std::string &filename, const Json &doc);
};


#endif //JSON_READ_WRITE_JSON_WORKER_H
