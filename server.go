package main

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/flynn/noise"
)

func startBeacon() {
	for {
		ifaces, _ := net.Interfaces()
		for _, iface := range ifaces {
			addrs, _ := iface.Addrs()
			for _, addr := range addrs {
				if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
					ipStr := ipnet.IP.String()

					// ФИЛЬТР: вещаем только если IP начинается на 192.168.
					// Это исключит адреса Radmin (26.x.x.x) и другие мусорные интерфейсы
					if strings.HasPrefix(ipStr, "192.168.") {

						broadcast := make(net.IP, len(ipnet.IP.To4()))
						for i := range ipnet.IP.To4() {
							broadcast[i] = ipnet.IP.To4()[i] | ^ipnet.Mask[i]
						}

						conn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: broadcast, Port: 9999})
						if err == nil {
							conn.Write([]byte("NOISE_SERVER_8080"))
							conn.Close()
						}
					}
				}
			}
		}
		time.Sleep(5 * time.Second)
	}
}

func shutdownPC() {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "windows":
		// На Windows: shutdown /s /t 30 /c "Компьютер выключается по команде"
		cmd = exec.Command("shutdown", "/s", "/t", "30", "/c", "Server initiated shutdown")
	case "linux":
		// На Linux: sudo shutdown -h +1
		cmd = exec.Command("sudo", "shutdown", "-h", "+1")
	case "darwin":
		// На macOS: osascript
		cmd = exec.Command("osascript", "-e", "tell application \"System Events\" to shut down")
	default:
		log.Printf("❌ Платформа %s не поддерживается\n", runtime.GOOS)
		return
	}

	err := cmd.Run()
	if err != nil {
		log.Printf("❌ Ошибка выключения: %v\n", err)
	} else {
		log.Printf("⚠️  Компьютер будет выключен через 30 секунд...\n")
	}
}

func main() {
	go startBeacon()
	listener, err := net.Listen("tcp", ":8080")
	if err != nil {
		log.Fatalf("❌ Ошибка прослушивания: %v", err)
	}
	defer listener.Close()
	log.Println("🚀 Сервер готов, маяк запущен...")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("❌ Ошибка приема соединения: %v", err)
			continue
		}
		go handleClient(conn)
	}
}

func handleClient(conn net.Conn) {
	defer conn.Close()

	// Устанавливаем таймаут на все операции
	deadline := time.Now().Add(30 * time.Second)
	conn.SetReadDeadline(deadline)
	conn.SetWriteDeadline(deadline)

	psk := sha256.Sum256([]byte("mylittle-r1xe<3"))
	keyID, err := noise.DH25519.GenerateKeypair(rand.Reader)
	if err != nil {
		log.Printf("❌ Ошибка генерации ключа: %v", err)
		return
	}

	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA256),
		Pattern:       noise.HandshakeXX,
		Initiator:     false,
		PresharedKey:  psk[:],
		StaticKeypair: keyID,
		Prologue:      []byte("demo-app-v1"),
	})
	if err != nil {
		log.Printf("❌ Ошибка инициализации handshake: %v", err)
		return
	}

	buf := make([]byte, 2048)

	// Читаем первое сообщение от клиента
	n, err := conn.Read(buf)
	if err != nil {
		log.Printf("❌ Ошибка чтения первого сообщения: %v", err)
		return
	}

	_, _, _, err = hs.ReadMessage(nil, buf[:n])
	if err != nil {
		log.Printf("❌ Ошибка при парсинге первого сообщения handshake: %v", err)
		return
	}

	// Отправляем второе сообщение
	msg, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		log.Printf("❌ Ошибка при создании второго сообщения: %v", err)
		return
	}

	_, err = conn.Write(msg)
	if err != nil {
		log.Printf("❌ Ошибка отправки второго сообщения: %v", err)
		return
	}

	// Читаем третье сообщение от клиента
	n, err = conn.Read(buf)
	if err != nil {
		log.Printf("❌ Ошибка чтения третьего сообщения: %v", err)
		return
	}

	_, recv, send, err := hs.ReadMessage(nil, buf[:n])
	if err != nil {
		log.Printf("❌ Ошибка при парсинге третьего сообщения handshake: %v", err)
		return
	}

	log.Println("✅ Клиент подключен")

	// Читаем зашифрованное сообщение от клиента
	n, err = conn.Read(buf)
	if err != nil {
		log.Printf("❌ Ошибка чтения зашифрованного сообщения: %v", err)
		return
	}

	plaintext, err := recv.Decrypt(nil, nil, buf[:n])
	if err != nil {
		log.Printf("❌ Ошибка расшифровки сообщения: %v", err)
		return
	}

	message := strings.TrimSpace(string(plaintext))
	log.Printf("📥 Получено: %s\n", message)

	// ГЛАВНОЕ: проверяем команду выключения
	if message == "shutdown" {
		log.Println("⚠️  КОМАНДА ВЫКЛЮЧЕНИЯ ПОЛУЧЕНА!")
		resp, err := send.Encrypt(nil, nil, []byte("shutdown_confirmed\n"))
		if err == nil {
			conn.Write(resp)
		}
		shutdownPC()
		return
	}

	// Обычный ответ
	resp, err := send.Encrypt(nil, nil, []byte("ok\n"))
	if err != nil {
		log.Printf("❌ Ошибка шифрования ответа: %v", err)
		return
	}

	_, err = conn.Write(resp)
	if err != nil {
		log.Printf("❌ Ошибка отправки ответа: %v", err)
	}
}
