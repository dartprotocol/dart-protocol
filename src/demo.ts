import { DartGroupServer } from './server';

console.log("Starting Dart Web Demo Server...");
const server = new DartGroupServer(9000);

console.log("UDP Server listening on 9000");
console.log("TCP Server listening on 9001");
console.log("HTTP / WebSocket Server listening on 9002");
console.log("\nOpen http://localhost:9002 in two browser tabs to chat!");
