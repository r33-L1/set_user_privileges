#include <Windows.h>
#include <ntsecapi.h>
#include <sddl.h>

#include <string>
#include <vector>
#include <iostream>

int win_error(const char* message) {
    std::cout << message << ::GetLastError() << std::endl;
    return 1;
}

void InitLsaString(PLSA_UNICODE_STRING lsaStr, LPWSTR str) {
    if (str == NULL) {
        lsaStr->Buffer = NULL;
        lsaStr->Length = 0;
        lsaStr->MaximumLength = 0;
        return;
    }

    DWORD l = wcslen(str);
    lsaStr->Buffer = str;
    lsaStr->Length = (USHORT)l * sizeof(WCHAR);
    lsaStr->MaximumLength = (USHORT)(l + 1) * sizeof(WCHAR);
}

void CheckRetVal(NTSTATUS res, ULONG okRetVal = ERROR_SUCCESS) {
    ULONG err = LsaNtStatusToWinError(res);
    if (err != ERROR_SUCCESS && err != okRetVal) {
        std::cout << err;
        exit(err);
    }
}

LSA_HANDLE OpenPolicy(DWORD accessMask) {
    LSA_OBJECT_ATTRIBUTES objectAttributes;
    ZeroMemory(&objectAttributes, sizeof(objectAttributes));
    LSA_UNICODE_STRING lsaMachineName;
    InitLsaString(&lsaMachineName, NULL);
    LSA_HANDLE hPolicy = NULL;

    CheckRetVal(LsaOpenPolicy(&lsaMachineName, &objectAttributes, accessMask, &hPolicy));

    return hPolicy;
}

void GetSid(PSID sid, LPDWORD pSidSize, LPCWSTR accountName) {
    SID_NAME_USE use;
    WCHAR referencedDomainName[1024];
    DWORD cchReferencedDomainName = sizeof(referencedDomainName) / sizeof(WCHAR);
    if (!::LookupAccountNameW(NULL, accountName, sid, pSidSize, referencedDomainName, &cchReferencedDomainName, &use))
    {
        win_error("Cannot find account");
    }
}

std::vector<std::wstring> GetPrivileges(PSID sid) {
    LSA_HANDLE hPolicy = OpenPolicy(POLICY_LOOKUP_NAMES);
    if (NULL == hPolicy)
        std::cout << "Error opening policy handle" << std::endl;
    PLSA_UNICODE_STRING userRights = NULL;

    try
    {
        ULONG rightsCount = 0;

        CheckRetVal(::LsaEnumerateAccountRights(hPolicy, sid, &userRights, &rightsCount), ERROR_FILE_NOT_FOUND);

        std::vector<std::wstring> v;
        for (int i = 0; i < rightsCount; i++)
        {
            std::wstring s(userRights[i].Buffer, userRights[i].Length / sizeof(WCHAR));
            v.push_back(s);
        }

        LsaFreeMemory(userRights);
        userRights = NULL;
        LsaClose(hPolicy);
        hPolicy = NULL;

        return v;
    }
    catch (const std::exception&)
    {
        if (userRights)
        {
            LsaFreeMemory(userRights);
        }

        if (hPolicy)
        {
            LsaClose(hPolicy);
        }

        throw;
    }
}

void GrantPrivilege(PSID sid, LPCWSTR userRight) {
    LSA_HANDLE hPolicy = OpenPolicy(POLICY_LOOKUP_NAMES | POLICY_CREATE_ACCOUNT);

    try
    {
        LSA_UNICODE_STRING lsaUserRight;
        InitLsaString(&lsaUserRight, (LPWSTR)userRight);
        CheckRetVal(LsaAddAccountRights(hPolicy, sid, &lsaUserRight, 1));

        LsaClose(hPolicy);
    }
    catch (const std::exception&)
    {
        LsaClose(hPolicy);
        throw;
    }
}

void RevokePrivilege(PSID sid, LPCWSTR userRight) {
    LSA_HANDLE hPolicy = OpenPolicy(POLICY_LOOKUP_NAMES);

    try
    {
        LSA_UNICODE_STRING lsaUserRight;
        InitLsaString(&lsaUserRight, (LPWSTR)userRight);
        CheckRetVal(LsaRemoveAccountRights(hPolicy, sid, FALSE, &lsaUserRight, 1));
        LsaClose(hPolicy);
    }
    catch (const std::exception&)
    {
        LsaClose(hPolicy);
        throw;
    }
}

int main(int argc, char* argv[]) {

    bool list   = false;
    bool add    = false;
    bool revoke = false;

    std::string help_message = "set_user_privilege.exe -a [--add] <privilege> -u <user/group>\n"
        "set_user_privilege.exe -l [--list] -u <user/group>\n"
        "set_user_privilege.exe -r [--revoke] <privilege> -u <user/group>\n";

    if (argc < 4) {
        std::cout << help_message;
        return 1;
    }

    std::string name;
    std::string privilege;

    if (std::string(argv[1]) == std::string("-a") || 
        std::string(argv[1]) == std::string("--add") || 
        std::string(argv[1]) == std::string("-r") || 
        std::string(argv[1]) == std::string("--revoke")) {
        if (argc != 5) {
            std::cout << help_message;
            return 1;
        }
        privilege = argv[2];
        if (std::string(argv[3]) != std::string("-u") && 
            std::string(argv[3]) != std::string("--user")) {
            std::cout << help_message;
            return 1;
        }
        name = argv[4];

        if (std::string(argv[1]) == std::string("-a") ||
            std::string(argv[1]) == std::string("--add"))
            add = true;
        else
            revoke = true;
    }

    if (std::string(argv[1]) == std::string("-l") || 
        std::string(argv[1]) == std::string("--list")) {
        if (std::string(argv[2]) != std::string("-u") && 
            std::string(argv[2]) != std::string("--user")) {
            std::cout << help_message;
            return 1;
        }
        name = argv[3];
        list = true;
    }

    // getting SID
    DWORD sidSize = 1024;
    PSID sid = malloc(sidSize);
    if (!sid)
    {
        throw std::exception("Malloc failed");
    }

    ZeroMemory(sid, sidSize);
    std::wstring wname = std::wstring(name.begin(), name.end());

    GetSid(sid, &sidSize, wname.c_str());

    LPSTR c_string_sid;

    if (!::ConvertSidToStringSidA(sid, &c_string_sid))
        win_error("Error converting to string");

    std::cout << "[+] Got SID: " << c_string_sid << std::endl;

    if (list) {
        std::vector<std::wstring>& user_privs = GetPrivileges(sid);
        if (user_privs.size() != 0)
            std::cout << "[+] Listing Privileges:" << std::endl;
        for (std::vector<std::wstring>::iterator it = user_privs.begin(); it != user_privs.end(); ++it) {
            std::wcout << *it << std::endl;
        }
        return 0;
    }

    std::wstring wprivilege = std::wstring(privilege.begin(), privilege.end());
    
    if (add) {
        GrantPrivilege(sid, wprivilege.c_str());
        std::cout << "[+] Assigned " << wprivilege.c_str() << " to user " << name << std::endl;
        return 0;
    }
    
    if (revoke) {
        RevokePrivilege(sid, wprivilege.c_str());
        std::cout << "[+] Revoked " << wprivilege.c_str() << " from user " << name << std::endl;
        return 0;
    }

    else
        return 1;

}