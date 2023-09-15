//
// Created by viktor on 24.02.23.
//
#include "json_worker.h"
#include <fstream>
#include <vector>

/** create empty JSON object */
Json JsonWorker::CreateJsonObject()
{
#if 0
    const char* json = "{}";
    Json jsonObj = std::make_shared<rapidjson::Document>();
    jsonObj->Parse(json);
    return jsonObj;
#endif
    return std::make_shared<rapidjson::Document>(rapidjson::kObjectType);
}


/** find and return string value from JSON object */
std::string JsonWorker::FindStringVal(const Json& _jsonObj, std::string _curKey)
{
    std::string val = "";

    rapidjson::Value::ConstMemberIterator itr = _jsonObj->FindMember(_curKey.data());
    if (itr != _jsonObj->MemberEnd())
        val = itr->value.GetString();

    return val;
}

#undef GetObject
/** change value from key in JSON object */
void JsonWorker::ChangeVal(const Json& _jsonObj, std::string _curKey, std::string _newVal)
{
    rapidjson::Value key;
    key.SetString(_curKey.data(),_curKey.size(), _jsonObj->GetAllocator());

    rapidjson::Value val;
    val.SetString(_newVal.data(), _newVal.size(), _jsonObj->GetAllocator());

    _jsonObj->GetObject()[key] = val;
}

/** serialize JSON object to string */
std::string JsonWorker::Serialize(const Json& _jsonObj)
{
    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    _jsonObj->Accept(writer);

    return buffer.GetString();
}

/** deserialize string to JSON object */
Json JsonWorker::Deserialize(const std::string& _serData)
{
    const char* json = _serData.data();
    Json jsonObj = std::make_shared<rapidjson::Document>();
    jsonObj->Parse(json);

    return jsonObj;
}

Json JsonWorker::ReadFromFile(const std::string &filename) {
    std::ifstream fin(filename);
    rapidjson::IStreamWrapper isw {fin};

    Json doc = JsonWorker::CreateJsonObject();
    doc->ParseStream(isw);

    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer {buffer};
    doc->Accept(writer);

    if (doc->HasParseError()) {
        WLI << "Error  : " << doc->GetParseError() << '\n'
            << "Offset : " << doc->GetErrorOffset() << '\n';
    }

    return doc;
}

void JsonWorker::SaveToFile(const std::string &filename, const Json &doc) {
    std::ofstream fout(filename);
    fout << Serialize(doc);
}
