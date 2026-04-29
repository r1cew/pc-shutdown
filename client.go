package main

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/flynn/noise"
)

func findServerByBeacon() (string, error) {
	addr := net.UDPAddr{Port: 9999, IP: net.ParseIP("0.0.0.0")}
	conn, err := net.ListenUDP("udp", &addr)
	if err != nil {
		return "", fmt.Errorf("ошибка при прослушивании UDP: %w", err)
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(15 * time.Second))

	buf := make([]byte, 1024)
	log.Println("📡 Ожидание сигнала сервера...")
	n, remoteAddr, err := conn.ReadFromUDP(buf)
	if err != nil {
		return "", fmt.Errorf("ошибка при получении beacon: %w", err)
	}

	if string(buf[:n]) == "NOISE_SERVER_8080" {
		return remoteAddr.IP.String() + ":8080", nil
	}
	return "", fmt.Errorf("неверный сигнал: %s", string(buf[:n]))
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Использование: client <hello|shutdown>")
		os.Exit(1)
	}

	command := os.Args[1]

	serverAddr, err := findServerByBeacon()
	if err != nil {
		log.Fatalf("❌ Ошибка поиска сервера: %v", err)
	}
	log.Println("✅ Сервер найден:", serverAddr)

	conn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		log.Fatalf("❌ Ошибка подключения: %v", err)
	}
	defer conn.Close()

	// Устанавливаем таймаут
	conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	conn.SetWriteDeadline(time.Now().Add(15 * time.Second))

	psk := sha256.Sum256([]byte("mylittle-r1xe<3"))
	keyID, err := noise.DH25519.GenerateKeypair(rand.Reader)
	if err != nil {
		log.Fatalf("❌ Ошибка генерации ключа: %v", err)
	}

	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA256),
		Pattern:       noise.HandshakeXX,
		Initiator:     true,
		PresharedKey:  psk[:],
		StaticKeypair: keyID,
		Prologue:      []byte("demo-app-v1"),
	})
	if err != nil {
		log.Fatalf("❌ Ошибка инициализации handshake: %v", err)
	}

	buf := make([]byte, 2048)

	// Первое сообщение
	msg, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		log.Fatalf("❌ Ошибка создания первого сообщения: %v", err)
	}

	_, err = conn.Write(msg)
	if err != nil {
		log.Fatalf("❌ Ошибка отправки первого сообщения: %v", err)
	}

	// Получение второго сообщения
	n, err := conn.Read(buf)
	if err != nil {
		log.Fatalf("❌ Ошибка чтения второго сообщения: %v", err)
	}

	_, _, _, err = hs.ReadMessage(nil, buf[:n])
	if err != nil {
		log.Fatalf("❌ Ошибка парсинга второго сообщения: %v", err)
	}

	// Третье сообщение
	msg, send, recv, err := hs.WriteMessage(nil, nil)
	if err != nil {
		log.Fatalf("❌ Ошибка создания третьего сообщения: %v", err)
	}

	_, err = conn.Write(msg)
	if err != nil {
		log.Fatalf("❌ Ошибка отправки третьего сообщения: %v", err)
	}

	// Отправляем команду
	var payload []byte
	switch command {
	case "shutdown":
		payload = []byte("shutdown\n")
		log.Println("⚠️  Отправляю команду выключения...")
	case "hello":
		payload = []byte("hello from client\n")
		log.Println("📤 Отправляю приветствие...")
	default:
		log.Fatalf("❌ Неизвестная команда: %s", command)
	}

	c, err := send.Encrypt(nil, nil, payload)
	if err != nil {
		log.Fatalf("❌ Ошибка шифрования: %v", err)
	}

	_, err = conn.Write(c)
	if err != nil {
		log.Fatalf("❌ Ошибка отправки команды: %v", err)
	}

	// Получаем ответ
	n, err = conn.Read(buf)
	if err != nil {
		log.Fatalf("❌ Ошибка чтения ответа: %v", err)
	}

	resp, err := recv.Decrypt(nil, nil, buf[:n])
	if err != nil {
		log.Fatalf("❌ Ошибка расшифровки ответа: %v", err)
	}

	log.Printf("✅ Ответ: %s", string(resp))
}
