#define _WINSOCKAPI_
#include <windows.h>
#include <sal.h>
#include <httpserv.h>
#include <string>
#include <map>
#include <vector>
#include <sstream>
#include <stdlib.h>
#include <fstream>
#include <iostream>
#include <unordered_map>
#include <time.h>
#include <direct.h>
#include <Windows.h>
#include <regex>


#include <boost\tokenizer.hpp>
#include <boost\algorithm\string.hpp>
#include <boost\date_time\posix_time\posix_time.hpp> 

#include "DataTable.h"
#include "CompactDog.h"

#define BS 32*1024

using namespace std;
using namespace boost;
using namespace boost::posix_time;

class guard_isapi : public CHttpModule
{
	std::unordered_map<std::string, ptime>  pm;
	//std::shared_ptr<CompactDog> factory;
	//wstring database;
	regex inj, incr;

public:
	REQUEST_NOTIFICATION_STATUS OnBeginRequest(IN IHttpContext * context, IN IHttpEventProvider * pProvider)
	{
		UNREFERENCED_PARAMETER(pProvider);

		IHttpRequest* request = context->GetRequest();
		IHttpResponse* response = context->GetResponse();

		try
		{
			if (request->GetRawHttpRequest()->Verb == HttpVerbGET)
			{
				if (!GET(context))
				{
					context->SetRequestHandled();
					return RQ_NOTIFICATION_FINISH_REQUEST;
				}
			}
			else if (request->GetRawHttpRequest()->Verb == HttpVerbPOST)
			{
				if (!POST(context))
				{
					context->SetRequestHandled();
					return RQ_NOTIFICATION_FINISH_REQUEST;
				}
			}
		}
		catch (std::exception& e)
		{
		}
		catch (...)
		{
		}

		return RQ_NOTIFICATION_CONTINUE;
	}

	bool GET(IN IHttpContext * context)
	{
		IHttpRequest* request = context->GetRequest();
		IHttpResponse* response = context->GetResponse();

		string raw_url(request->GetRawHttpRequest()->pRawUrl, request->GetRawHttpRequest()->RawUrlLength);
		raw_url = decode(raw_url);

		std::string qs = "";
		if (raw_url.find_first_of("?") != std::string::npos)
		{
			qs = raw_url.substr(raw_url.find_first_of("?") + 1);
		}

		if (qs.size() < 1)
			return true;

		std::vector<std::string> pairs = parse(qs, "&");
		std::map<std::string, std::string> Q;


		for (int i = 0; i < pairs.size(); i++)
		{
			size_t pos = pairs[i].find_first_of("=");

			if (pos == string::npos)
				continue;

			Q[pairs[i].substr(0, pos)] = pairs[i].substr(pos + 1);
		}

		//incursion check for only php files
		string page = raw_url.substr(1, raw_url.find_first_of("?") - 1);
		string ext = page.substr(page.find_last_of(".") + 1);

		if (equals(ext, "php"))
		{
			if (incursive(context, Q, page))
				return false;
		}

		for (std::map<std::string, std::string>::iterator it = Q.begin(); it != Q.end(); it++)
		{
			match_results<std::string::const_iterator> mr;
			string in_text = decode(it->second);
			if (regex_search(in_text, mr, inj))
			{
				for (int i = 0; i < mr.size(); ++i)
				{
					if (!mr[i].matched)
						continue;

					log(in_text, mr[i].str(), inet_ntoa(((sockaddr_in*)context->GetRequest()->GetRemoteAddress())->sin_addr), context);

					break;
				}
				return false;
			}
		}
		return true;
	}

	bool POST(IN IHttpContext * context)
	{
		string pt = get_request_header(context, "Content-Type");

		if (pt.find("x-www-form-urlencoded") != string::npos)
		{
			return x_www_form_urlencoded(context);
		}
		else if (pt.find("multipart/form-data") != string::npos)
		{
			return multipart_formdata(context);
		}
		return true;
	}

	bool incursive(IHttpContext* context, std::map<std::string, std::string> Q, const std::string& page)
	{
		for (std::map<std::string, std::string>::iterator it = Q.begin(); it != Q.end(); it++)
		{
			match_results<std::string::const_iterator> mr;
			string in_text = decode(it->second);
			if (regex_search(in_text, mr, incr))
			{
				for (int i = 0; i < mr.size(); ++i)
				{
					if (!mr[i].matched)
						continue;

					log(in_text, mr[i].str(), inet_ntoa(((sockaddr_in*)context->GetRequest()->GetRemoteAddress())->sin_addr), context);

					break;
				}
				return true;
			}
		}

		return false;
	}
	bool x_www_form_urlencoded(IHttpContext* context)
	{
		if (context->GetRequest()->GetRemainingEntityBytes() < 1)
			return true;

		stringstream eb;

		while (context->GetRequest()->GetRemainingEntityBytes() != 0)
		{
			char* pchr = static_cast<char*>(context->AllocateRequestMemory(BS));
			memset(pchr, 0, BS);

			if (pchr == 0)
				return false;

			DWORD cbrec = 0;
			context->GetRequest()->ReadEntityBody(static_cast<void*>(pchr), BS - 2, false, &cbrec);

			eb << pchr;
		}

		if (eb.rdbuf()->in_avail() == 0)
			return true;

		string req(eb.str());

		std::vector<std::string> pairs = parse(req, "&");
		std::map<std::string, std::string> Form;


		for (int i = 0; i < pairs.size(); i++)
		{
			size_t pos = pairs[i].find_first_of("=");

			if (pos == string::npos)
				continue;

			Form[pairs[i].substr(0, pos)] = pairs[i].substr(pos + 1);
		}

		for (std::map<std::string, std::string>::iterator it = Form.begin(); it != Form.end(); it++)
		{
			if (equals(it->first, "__VIEWSTATE") || equals(it->first, "__EVENTVALIDATION"))
				continue;


			match_results<std::string::const_iterator> mr;
			string in_text = decode(it->second);
			if (regex_search(in_text, mr, inj))
			{
				for (int x = 0; x < mr.size(); ++x)
				{
					if (mr[x].matched == true)
					{

						log(in_text, mr[x].str(), inet_ntoa(((sockaddr_in*)context->GetRequest()->GetRemoteAddress())->sin_addr), context);

						return false;
					}
				}
				return false;
			}
		}

		return true;
	}

	bool multipart_formdata(IHttpContext* context)
	{
		if (context->GetRequest()->GetRemainingEntityBytes() < 1)
			return true;

		stringstream eb;

		while (context->GetRequest()->GetRemainingEntityBytes() != 0)
		{
			char* pchr = static_cast<char*>(context->AllocateRequestMemory(BS));
			memset(pchr, 0, BS);

			if (pchr == 0)
				return false;

			DWORD cbrec = 0;
			context->GetRequest()->ReadEntityBody(static_cast<void*>(pchr), BS, false, &cbrec);

			eb << pchr;
		}

		if (eb.rdbuf()->in_avail() == 0)
			return true;

		string rt(eb.str());

		map<string, string> Form;
		string line;
		bool bpp = false;

		while (!eb.eof())
		{
			getline(eb, line);
			if (starts_with(line, "--"))
			{
				string subline;
				if (eb.eof())
					break;

				getline(eb, subline);
				if (!starts_with(subline, "Content-Disposition"))
				{
					eb.seekg(-subline.size(), ios::cur);
					continue;//fake start
				}

				vector<string> pairs = parse(subline, ";");
				string form_elem_id;
				bool bfileupload = false;
				for (int i = 0; i < pairs.size(); i++)
				{
					size_t pos = pairs[i].find_first_of("=");
					if (pos == string::npos)
						continue;

					string p1 = pairs[i].substr(0, pos);
					trim(p1);

					if (equals(p1, "name"))
						form_elem_id = pairs[i].substr(pos + 1);
					else if (equals(p1, "filename"))
					{
						bfileupload = true;
						break;
					}
				}
				if (bfileupload)
					continue;//skip files
				if (form_elem_id.size() < 1)
					continue;//skip invalid ;
				if (equals(form_elem_id, "__VIEWSTATE") || equals(form_elem_id, "__EVENTVALIDATION"))
					continue;//refuse asp.net driven values

				Form[form_elem_id] = "";

				while (!eb.eof())
				{
					if (eb.eof())
						break;

					getline(eb, subline);

					if (!equals(subline, "\r"))
						continue;

					//the following is the next fv
					if (eb.eof())
						break;

					getline(eb, subline);
					Form[form_elem_id] = subline.substr(0, subline.size() - 1);
					break;
				}
			}
		}

		for (std::map<std::string, std::string>::iterator it = Form.begin(); it != Form.end(); it++)
		{
			string in_text = decode(it->second);
			match_results<std::string::const_iterator> mr;
			if (regex_search(in_text, mr, inj))
			{
				for (int i = 0; i < mr.size(); ++i)
				{
					if (!mr[i].matched)
						continue;

					log(in_text, mr[i].str(), inet_ntoa(((sockaddr_in*)context->GetRequest()->GetRemoteAddress())->sin_addr), context);

					break;
				}
				return false;
			}
		}

		return true;
	}

	std::vector<std::string> parse(IN const std::string& _input, std::string del)
	{
		std::vector<std::string> results;

		boost::char_separator<char> sep(del.c_str());

		boost::tokenizer<boost::char_separator<char> > tokens(_input, sep);

		for (boost::tokenizer<boost::char_separator<char> >::iterator tok_iter = tokens.begin(); tok_iter != tokens.end(); ++tok_iter)
		{
			results.push_back(*tok_iter);
		}

		return results;
	}

	std::string decode(IN const std::string& url)
	{
		string ret;
		ret.reserve(url.size());

		for (size_t i = 0; i < url.size(); i++)
		{
			if (url[i] != '%' &&  url[i] != '+')
			{
				ret += url[i];
				continue;
			}

			if (url[i] == '%')
			{
				//possible encoded char
				if ((i + 2) <= url.size())
				{
					//well formed it is
					char* endpoint = 0;
					char c = static_cast<char>(strtol(url.substr(i + 1, 2).c_str(), &endpoint, 16));

					ret += c;
					i += 2;
				}
			}
			else if (url[i] == '+')
				ret += ' ';//just a space
		}
		return ret;
	}

	std::string get_request_header(IN IHttpContext* context, IN const std::string& _name)
	{
		PCSTR var = static_cast<char*>(context->AllocateRequestMemory(256));
		USHORT len = 256;

		var = context->GetRequest()->GetHeader(HttpHeaderContentType, &len);
		return string(var, len);
	}
	std::string get_response_header(IN IHttpContext* context, IN const std::string& _name)
	{
		PCSTR var = static_cast<char*>(context->AllocateRequestMemory(256));
		USHORT len = 256;

		var = context->GetResponse()->GetHeader(HttpHeaderContentType, &len);
		return string(var, len);
	}

	std::string now()
	{
		time_t rawtime;
		struct tm * timeinfo;
		char buffer[80];

		time(&rawtime);
		timeinfo = localtime(&rawtime);

		memset(buffer, 0, 80);

		strftime(buffer, 80, "%Y.%m.%d %H:%M:%S", timeinfo);
		return string(buffer);
	}

	void log(std::string in_text, std::string found, std::string addr, IHttpContext* context)
	{
		//string raw_url(context->GetRequest()->GetRawHttpRequest()->pRawUrl, context->GetRequest()->GetRawHttpRequest()->RawUrlLength);
		//raw_url = decode(raw_url);

		//std::shared_ptr<DbConnection> cnn = factory->GetConnection(database);
		//cnn->Open();
		//std::shared_ptr<DbCommand> cmd = factory->GetCommand(L"SELECT * FROM memoriae", cnn);
		//std::shared_ptr<DbDataAdapter> adapter = factory->GetAdapter(cmd);
		//
		//DataTable dt;

		//adapter->FillSchema(dt);

		//Row r = dt.NewRow();


		//replace_all(in_text, "'", "''");
		//replace_all(found, "'", "''");

		//r[L"_ip"] = addr;
		//r[L"_in_text"] = in_text;
		//r[L"_found"] = found;
		//r[L"_date"] = now();
		//
		//string sayfa = "";

		//size_t pos = raw_url.find_last_of("/");
		//if( pos != string::npos )
		//{
		//	sayfa = raw_url.substr( pos, raw_url.find_first_of("?") );
		//}				
		//
		//r[L"page"] = sayfa;

		//dt.Rows.Add(r);

		//adapter->Update(dt);
	}


	guard_isapi()
	{
		//factory.reset(new CompactDog());


		//these two regex needs alot improvement
		string pattern = "([\\'\\;]+[\\s\\(]*select\\s*([\\w\\(\\)\\,\\s]+|(\\*)+)\\s*from(\\s+|\\W+)\\w+)"
			"|([\\'|\\;\\s]+or[\\s\\(]+[\\(\\s]*\\w+[\\)\\s]*=[\\(\\s]*\\w+[\\)\\s]*)"
			"|(insert\W+(into[a-zA-Z0-9\\(\\)\\-\\_\\S])?[a-zA-Z0-9]+=)"
			"|(delete\\W+(from)+\\W+\\w+)"
			"|(drop\\W+(table)+\\w+)"
			"|(update\\W+\\w+\\W+(set)+\\W+)"
			;

		string incursion_pattern = "^([a-zA-Z]{3,9}:\\/\\/){0,1}([a-zA-Z0-9\\-]+\\.)*([a-zA-Z0-9\\-]{2,6}\\/)"
			"{1}([a-zA-Z0-9\\-\\_]+\\/)*([a-zA-Z0-9\\-\\_]+\\.[a-zA-Z0-9\\-\\_]+){1}";

		//database = L"database=C:\\guard_isapi\\memoriae_custodi.sdf";


		//imbue with some other local
		//inj.imbue( 1055 );
		inj.assign(pattern, std::regex_constants::collate | std::regex_constants::icase | std::regex_constants::ECMAScript);

		incr.assign(incursion_pattern, std::regex_constants::ECMAScript);
	}
};

class guard_isapi_factory : public IHttpModuleFactory
{
public:
	HRESULT GetHttpModule(OUT CHttpModule ** ppModule, IN IModuleAllocator * pAllocator)
	{
		UNREFERENCED_PARAMETER(pAllocator);

		guard_isapi * pModule = new guard_isapi;

		if (!pModule)
		{
			return HRESULT_FROM_WIN32(ERROR_NOT_ENOUGH_MEMORY);
		}
		else
		{
			*ppModule = pModule;
			pModule = NULL;
			return S_OK;
		}
	}

	void Terminate()
	{
		delete this;
	}
};

HRESULT __stdcall RegisterModule(DWORD dwServerVersion, IHttpModuleRegistrationInfo * pModuleInfo, IHttpServer * pGlobalInfo)
{
	UNREFERENCED_PARAMETER(dwServerVersion);
	UNREFERENCED_PARAMETER(pGlobalInfo);

	return pModuleInfo->SetRequestNotifications(new guard_isapi_factory, RQ_BEGIN_REQUEST, 0);
}

string utf82ansi(const string& input)
{
	int sizeRequired = MultiByteToWideChar(CP_UTF8, 0, input.c_str(), input.size(), NULL, NULL);

	wchar_t* wout = new wchar_t[sizeRequired + 1];

	memset(wout, 0, (sizeRequired + 1) * sizeof(wchar_t));

	char* ansi = new char[sizeRequired + 5];

	memset(ansi, 0, (sizeRequired + 5));

	MultiByteToWideChar(CP_UTF8, 0, input.c_str(), -1, wout, sizeRequired);

	WideCharToMultiByte(28599, 0, wout, -1, ansi, sizeRequired, NULL, NULL);

	string ret(ansi);

	delete wout;
	delete ansi;

	return ret;
}

