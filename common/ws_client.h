#ifndef __WS_CLIENT_H__
#define __WS_CLIENT_H__
#include <websocketpp/config/asio_no_tls_client.hpp>
#include <websocketpp/client.hpp>
#include <iostream>
#include <chrono>
#include <thread>

typedef websocketpp::client<websocketpp::config::asio_client> client;

using websocketpp::lib::placeholders::_1;
using websocketpp::lib::placeholders::_2;
using websocketpp::lib::bind;
typedef websocketpp::connection_hdl connection_hdl;  // 正确定义 connection_hdl

// pull out the type of messages sent by our config
typedef websocketpp::config::asio_client::message_type::ptr message_ptr;

typedef void (*func_on_message)(client* c, websocketpp::connection_hdl hdl, message_ptr msg);

class ws_client {
public:
	ws_client(func_on_message p) {
		m_client.init_asio();
		m_client.set_open_handler(bind(&ws_client::on_open, this, ::_1));
		m_client.set_close_handler(bind(&ws_client::on_close, this, ::_1));
		m_client.set_message_handler(bind(&ws_client::on_message, this, ::_1, ::_2));
		p_on_message = p;
	}
	~ws_client(){
		m_connected = false;
	}

	void run(const std::string& uri) {
		websocketpp::lib::error_code ec;
		client::connection_ptr con = m_client.get_connection(uri, ec);
		m_hdl = con->get_handle();

		if (ec) {
			std::cout << "Connection failed: " << ec.message() << std::endl;
			return;
		}

		m_client.connect(con);
		m_client.run();
	}

	// 终止 ping 线程的函数
	void stop_ping_thread() {
		if (m_ping_thread.joinable()) {
			m_connected = false; // 设置标志位，通知线程退出
			m_ping_thread.join(); // 等待线程完成
		}
	}

	void on_open(connection_hdl hdl) {
		// 终止 ping 线程的函数
		stop_ping_thread();
		m_connected = true;
		// 启动心跳定时器，每隔 1 分钟发送一次 ping
		m_ping_thread = std::thread([this, hdl]() {

			while (m_connected) {
				std::this_thread::sleep_for(std::chrono::seconds(30)); // 每分钟发送 ping
				if (m_connected)
				{
					std::cout << "send heartbeat " << std::endl;
					try
					{
						client::connection_ptr con = m_client.get_con_from_hdl(hdl);
						if (con->get_state() == websocketpp::session::state::open)
							m_client.send(hdl, "heartbeat5", 10, websocketpp::frame::opcode::value::text);
					}
					catch (const std::exception&)
					{
						std::cout << "send heartbeat failed " << std::endl;
					}

				}
			}
			});
		m_ping_thread.detach();
	}

	void on_message(connection_hdl hdl, client::message_ptr msg) {
		std::cout << "Message received: " << msg->get_payload() << std::endl;
		p_on_message(&m_client, hdl, msg);
	}

	void on_close(connection_hdl hdl) {
		std::cout << "Connection closed" << std::endl;
		m_connected = false;
	}

private:
	client m_client;
	std::thread m_ping_thread;  // 定时发送 ping 的线程
	connection_hdl m_hdl;
	func_on_message p_on_message;
	std::atomic<bool> m_connected = false;
};

//int main() {
//	heartbeat_client c;
//	c.run("ws://localhost:9002");
//}

#endif //__WS_CLIENT_H__