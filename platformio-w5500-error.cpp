#include <Arduino.h>
#include <libssh_esp32.h>
#include "libssh_esp32_config.h"
#include <libssh/libssh.h>
#include <vector>
#include <string>
#include <Ethernet2.h>

byte mac[] = {0x00, 0xAA, 0xBB, 0xCC, 0xDE, 0x02}; // Your Ethernet shield MAC address
IPAddress ip(192, 168, 1, 67);
char server[] = "www.google.com";
EthernetClient client;

const int ssh_port = 22;
const char *ssh_username = "tgw";
const char *ssh_password = "heslo";
const char *ssh_command = "ls -l";

std::vector<std::string> server_ips = {
	"192.168.1.254",
};

// Globální SSH session pro opakované použití
ssh_session session = NULL;

void initSSH()
{
	if (session == NULL)
	{
		session = ssh_new();
		if (session == NULL)
		{
			Serial.println("Failed to create SSH session");
			return;
		}
	}
}

void cleanupSSH()
{
	if (session != NULL)
	{
		ssh_free(session);
		session = NULL;
	}
}

void executeSSHCommand(const char *ip, const char *username, const char *password, const char *command)
{
	// Create a new SSH session
	ssh_session session = ssh_new();
	if (session == NULL)
	{
		Serial.println("Failed to create SSH session");
		return;
	}

	// Set SSH options for the session
	ssh_options_set(session, SSH_OPTIONS_HOST, ip);
	ssh_options_set(session, SSH_OPTIONS_USER, username);
	ssh_options_set(session, SSH_OPTIONS_PORT, &ssh_port);

	// Connect to SSH server
	int rc = ssh_connect(session);
	if (rc != SSH_OK)
	{
		Serial.println("Failed to connect to SSH server");
		return;
	}

	// Verify the server's identity
	rc = ssh_userauth_password(session, NULL, password);
	if (rc != SSH_AUTH_SUCCESS)
	{
		Serial.println("Failed to authenticate");
		return;
	}

	// Create a new SSH channel
	ssh_channel channel = ssh_channel_new(session);
	if (channel == NULL)
	{
		Serial.println("Failed to create SSH channel");
		return;
	}

	// Open a new SSH session
	rc = ssh_channel_open_session(channel);
	if (rc != SSH_OK)
	{
		Serial.println("Failed to open SSH session");
		return;
	}

	// Execute the command
	rc = ssh_channel_request_exec(channel, command);
	if (rc != SSH_OK)
	{
		Serial.println("Failed to execute command");
		return;
	}

	// Read the output of the command
	char buffer[256];
	int nbytes; // Number of bytes read
	nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
	while (nbytes > 0)
	{
		if (write(1, buffer, nbytes) != nbytes) // Write to stdout
		{
			Serial.println("Failed to write to stdout");
			return;
		}
		nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
	}

	// Check if there was an error reading from the channel
	if (nbytes < 0)
	{
		Serial.println("Failed to read from SSH channel");
		return;
	}

	// Send EOF and close the channel
	ssh_channel_send_eof(channel);

	// Close the channel
	ssh_channel_close(channel);

	// Free the channel
	ssh_channel_free(channel);

	// Disconnect the session
	ssh_disconnect(session);

	// Free the session
	ssh_free(session);
}

void executeSSHCommandOnAllServers(const char *username, const char *password, const char *command)
{
	for (std::string ip : server_ips)
	{
		executeSSHCommand(ip.c_str(), username, password, command);
	}
}

void setup()
{
	Serial.begin(115200);
	while (!Serial)
	{
		; // wait for serial port to connect. Needed for Leonardo only
	}

	Ethernet.init(5);

	// Start Ethernet with DHCP
	if (Ethernet.begin(mac) == 0)
	{
		Serial.println("Failed to configure Ethernet using DHCP");
		// Try with static IP if DHCP fails
		Ethernet.begin(mac, ip);
	}

	// give the Ethernet shield a second to initialize:
	delay(1000);

	Serial.print("My IP address: ");
	for (byte thisByte = 0; thisByte < 4; thisByte++)
	{
		// print the value of each byte of the IP address:
		Serial.print(Ethernet.localIP()[thisByte], DEC);
		Serial.print(".");
	}
	Serial.println();

	ssh_init();
	initSSH();

	executeSSHCommandOnAllServers(ssh_username, ssh_password, ssh_command);

	cleanupSSH();

	if (client.connect(server, 80))
	{
		Serial.println("connected");
		// Make a HTTP request:
		client.println("GET /search?q=arduino HTTP/1.1");
		client.println("Host: www.google.com");
		client.println("Connection: close");
		client.println();
	}
	else
	{
		// kf you didn't get a connection to the server:
		Serial.println("connection failed");
	}
}

void loop()
{
	if (client.available())
	{
		char c = client.read();
		Serial.print(c);
	}

	// if the server's disconnected, stop the client:
	if (!client.connected())
	{
		Serial.println();
		Serial.println("disconnecting.");
		client.stop();

		// do nothing forevermore:
		while (true)
		{
			delay(1000);
		}
	}
	// Delay for 1 second
}
