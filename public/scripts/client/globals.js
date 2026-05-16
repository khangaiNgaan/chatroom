// public/scripts/client/globals.js

/* UI Elements */
const chatWindow = document.getElementById('chat-window');
const chatForm = document.getElementById('chat-form');
const roomList = document.getElementById('room-list');
const messageInput = document.getElementById('message-input');
const statusText = document.getElementById('status');
const retryButton = document.getElementById('retryButton');
const reloadButton = document.getElementById('reloadButton');

/* Room Configuration */
const ROOMS = ["bulletin", "general", "irl", "news", "debug", "minecraft"];
const ROOM_PLACEHOLDERS = {
    "general": "input...",
    "irl": "life with gas meter...",
    "news": "what's happening...",
    "debug": "debug the world...",
    "minecraft": "baked potatoes...",
    "bulletin": "iteration..."
};

let currentSocket = null;
let currentRoom = "general";
let currentUser = null;
let oldestMsgId = null;
let isLoadingHistory = false;
