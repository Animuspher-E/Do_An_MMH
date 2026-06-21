/**
 * File: database.js
 * Thuộc thư mục: models/ (Tầng Dữ Liệu)
 * Vai trò thư mục: Nơi cấu trúc và giữ các bản ghi State của toàn bộ người dùng và biến Registry (Mock Database).
 * 
 * Chức năng chính file này: Tách các biến lưu trữ toàn cục (global state) từ file server.js nguyên khối cũ sang đây để giải phóng dung lượng RAM, dễ trích xuất và bảo vệ dữ liệu chống Over-write. 
 */
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const users = {
    "24521658": { role: "Citizen", name: "Nguyen Van A", password: "123", hasCert: false, p12Path: "", hasRemoteCert: false, signPin: "", remoteKeyPath: "", remoteCrtPath: "" },
    "24521111": { role: "Citizen", name: "Tran Thi B", password: "123", hasCert: false, p12Path: "", hasRemoteCert: false, signPin: "", remoteKeyPath: "", remoteCrtPath: "" }
};
let signatureRegistry = {};
let pdfCache = {};
let globalSignedHistory = [];
let nonceCache = new Set();

module.exports = { users, signatureRegistry, pdfCache, globalSignedHistory, nonceCache };
