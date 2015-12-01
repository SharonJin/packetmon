#pragma once
#include <string>
#include <algorithm>
#include <winhttp.h>

namespace packetmon {
    class winhttp {
    private:
        std::wstring _host;
        std::wstring _path;
        bool _use_https;
    public:
        winhttp(std::wstring host, std::wstring path, bool use_https) :
            _host(host), _path(path), _use_https(use_https) {}
        // post msg={rp.comment}
        bool post(std::string str) {
            HINTERNET hSession = WinHttpOpen(L"packetmon/1.0",
                WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                WINHTTP_NO_PROXY_NAME,
                WINHTTP_NO_PROXY_BYPASS, 0);

            if (!hSession) {
                WinHttpCloseHandle(hSession);
                return false;
            }
            HINTERNET hConnect = WinHttpConnect(hSession, _host.c_str(),
                INTERNET_DEFAULT_HTTP_PORT, 0);

            // Create an HTTP request handle.
            if (!hConnect) {
                WinHttpCloseHandle(hConnect);
                WinHttpCloseHandle(hSession);
                return false;
            }
            HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", _path.c_str(),
                NULL, WINHTTP_NO_REFERER,
                WINHTTP_DEFAULT_ACCEPT_TYPES,
                _use_https == true ? WINHTTP_FLAG_SECURE : 0 /* WINHTTP_FLAG_SECURE */);

            if (!hRequest) {
                WinHttpCloseHandle(hConnect);
                WinHttpCloseHandle(hSession);
                WinHttpCloseHandle(hRequest);
                return false;
            }

            std::string msg = std::string("msg=") + str;
            std::replace(msg.begin(), msg.end(), ' ', '+');
            std::replace(msg.begin(), msg.end(), '\n', '+');
            std::wstring reqheader = L"Content-Type: application/x-www-form-urlencoded";
            std::string reqbody(msg.begin(), msg.end());
            BOOL bret = WinHttpSendRequest(hRequest,
                reqheader.c_str(), (DWORD)reqheader.length(),
                (void*)reqbody.c_str(),
                (DWORD)reqbody.length(),
                (DWORD)reqbody.length(),
                (DWORD_PTR)0);

            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            WinHttpCloseHandle(hRequest);

            return bret == TRUE ? true : false;
        }
    };
}
