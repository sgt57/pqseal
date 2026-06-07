import { createPQSealClient, createPQSealServer } from '../dist/index.js';

const server = createPQSealServer();
const client = createPQSealClient();

const bundle = server.issueChallenge();
const sealed = client.sealJson(bundle, {
  username: 'alice',
  password: 'correct horse battery staple'
});

console.log(server.openJson(sealed));
server.close();
