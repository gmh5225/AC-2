#include "CClientHandler.hpp"

CClientHandler::CClientHandler(std::size_t threadCount)
    : m_ThreadClients(threadCount), m_Mutexes(threadCount), m_ThreadCount(threadCount)
{

}

CClientHandler::~CClientHandler() 
{

}

void CClientHandler::addClient(ClientGUID guid, std::shared_ptr<CClient> client)
{
    std::lock_guard<std::mutex> addLock(m_AddClientMutex);

    ThreadID tid = 0;
    std::size_t currSize = std::numeric_limits<std::size_t>::max();

    for (std::size_t i = 0; i < m_ThreadCount; i++) {
        std::lock_guard<std::mutex> lock(m_Mutexes[i]);
        if (m_ThreadClients[i].size() < currSize) {
			currSize = m_ThreadClients[i].size();
			tid = i;
		}
    }

    //Add client for corresponding thread
    std::lock_guard<std::mutex> lock(m_Mutexes[tid]);
    m_ThreadClients.at(tid).insert({ guid, client });
}