#pragma once

#include <unordered_map>
#include <memory>
#include <mutex>
#include "CClient.hpp"
#include "Types.hpp"

using ClientHashMap = std::unordered_map<ClientGUID, std::shared_ptr<CClient>>;
using ThreadID = std::uint16_t;

class CClientHandler {

    std::unordered_map<ThreadID, ClientHashMap> m_ThreadClients;
    std::vector<std::mutex> m_Mutexes;
    std::size_t m_ThreadCount;
    std::mutex m_AddClientMutex;

public:

    CClientHandler(std::size_t threadCount);
    ~CClientHandler();

    void addClient(ClientGUID guid, std::shared_ptr<CClient> client);

    inline auto& getClientHashMap(ThreadID tid) {
		return m_ThreadClients.at(tid);
	}

    inline auto& getClientHashMapMutex(ThreadID tid) {
        return m_Mutexes.at(tid);
    }
};