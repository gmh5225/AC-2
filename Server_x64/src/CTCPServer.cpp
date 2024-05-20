#include "CTCPServer.hpp"
#include "Types.hpp"
#include "openssl/RSA.hpp"
#include "packet/Packet.hpp"
#include <vector>

CTCPServer::CTCPServer(boost::asio::ip::port_type port, std::uint16_t numOnConnectThreads, std::uint16_t numHandleConnectionThreads)
    : m_Acceptor(m_IOService, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port)), m_Stop(false), 
    m_NumOnConnectThreads(numOnConnectThreads), m_NumHandleConnectionThreads(numHandleConnectionThreads)
{
    m_ThreadPool = std::make_unique<CThreadPool>(numOnConnectThreads + numHandleConnectionThreads + 1);
    m_ClientHandler = std::make_unique<CClientHandler>(numHandleConnectionThreads);
}

CTCPServer::~CTCPServer() {
    
}

bool CTCPServer::start() {
    //Assign thread to clientAccept
    m_ThreadPool->addTask([this]() {
        acceptConnections();
    });

    //Assign threads to handleConnections
    for (std::uint16_t i = 0; i < m_NumHandleConnectionThreads; i++) {
        m_ThreadPool->addTask([this, i]() {
			handleConnections(i);
		});
	}

    return true;
}

void CTCPServer::stop()
{
	m_Stop = true;
	m_IOService.stop();
}

void CTCPServer::acceptConnections() {
    while (!m_Stop) {
        boost::asio::ip::tcp::socket socket(m_IOService);
        m_Acceptor.accept(socket);

        //Handle new connection in thread from pool
        auto clientSocket = std::make_shared<CTCPServerSocket>(std::move(socket));
        m_ThreadPool->addTask([this, clientSocket]() {
            handleOnConnect(clientSocket);
        });
    }
}

void CTCPServer::handleConnections(ThreadID tid)
{
    std::cout << "Handling connections on thread " << tid << std::endl;

    //Get client hash map and corresponding mutex
    auto& clientHashMap = m_ClientHandler->getClientHashMap(tid);
    auto& clientHashMapMutex = m_ClientHandler->getClientHashMapMutex(tid);

    while (!m_Stop) {

        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

void CTCPServer::handleOnConnect(std::shared_ptr<CTCPServerSocket> clientSocket) {
    //Generate encryption context
    ENCRYPTION_CONTEXT encryptionCtx = {};
    auto rsaKeyPair = RSA_OSSL::generateKeyPair(2048);
    if (!rsaKeyPair.has_value()) return;
    encryptionCtx.rsaKey = rsaKeyPair->privKey;

    //Handle handshake
    std::vector<unsigned char> pubkeyBuffer(rsaKeyPair->pubKey.begin(), rsaKeyPair->pubKey.end());
    if (!CPacket::send(clientSocket.get(), PacketType::AUTH_RSA_PUBKEY, pubkeyBuffer)) return;

    //Receive aes key
    auto aesPacket = CPacket::recv(clientSocket.get());
    if (!aesPacket.has_value()) return;

    //Decrypt aes key
    std::vector<unsigned char> aesKey = RSA_OSSL::decryptPrivate(aesPacket->getPayload(), rsaKeyPair->privKey);
    aesKey.resize(32);
    encryptionCtx.aesKey = aesKey;

    //Get client GUID
    if (!CPacket::send(clientSocket.get(), PacketType::GET_GUID)) return;

    auto guidPacket = CPacket::recv(clientSocket.get(), encryptionCtx.aesKey);
    if (!guidPacket.has_value()) return;

    ClientGUID clientGuid(guidPacket->getPayload().begin(), guidPacket->getPayload().end());

    //Add client for specific thread
    m_ClientHandler->addClient(clientGuid, std::make_shared<CClient>(clientSocket));
}