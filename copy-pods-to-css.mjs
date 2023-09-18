#!/usr/bin/env node
import assert from 'node:assert';
import { resolve } from 'node:path';
import { opendir, readFile } from 'node:fs/promises';

const expectedArgs = {
  'nss/config.json': 'path to the NSS configuration file',
};

main(...process.argv).catch(console.error);

// Starts migration with the command-line arguments
async function main(bin, script, ...args) {
  if (args.length !== Object.keys(expectedArgs).length) {
    process.stderr.write(`usage: ${script.replace(/.*\//, '')} ${
      Object.keys(expectedArgs).join(' ')}\n${
      Object.entries(expectedArgs).map(([example, description]) =>
        `    ${example}:\t${description}`).join('\n')}\n`);
    process.exit(1);
  }
  return copyNssPodsToCSS(...args);
}

// Copies the pods and accounts from NSS disk storage
// to a CSS instance and associated disk storage
async function copyNssPodsToCSS(nssConfigPath) {
  print('1️⃣  NSS: Read pod configurations from disk');
  const nss = await readNssConfig(nssConfigPath);
  const pods = await readPodConfigs(nss.dbPath);
  print(`Found ${pods.length} pods`);
}

// Reads the configuration of an NSS instance
async function readNssConfig(configPath) {
  assert.match(configPath, /config\.json$/, 'Invalid NSS config.json');
  const configFolder = resolve(configPath, '../');
  const config = await readJson(configPath);
  return {
    dbPath: resolve(configFolder, config.dbPath),
    dataPath: resolve(configFolder, config.root),
  };
}

// Reads the configurations of all pods from the NSS database
async function readPodConfigs(dbPath) {
  const configs = [];
  const usersPath = resolve(dbPath, 'oidc/users/users/');
  for await (const entry of await opendir(usersPath)) {
    if (entry.isFile() && entry.name.endsWith('.json')) {
      try {
        configs.push(await readPodConfig(resolve(usersPath, entry.name)));
      }
      catch { /* Skip invalid pods */ }
    }
  }
  return configs;
}

// Reads the configuration of a single pod from the NSS database
async function readPodConfig(configPath) {
  const pod = await readJson(configPath);
  const checks = {
    username: !!pod.username,
    password: (pod.hashedPassword || '').startsWith('$2a$10$'),
    webId: !!pod.webId,
  };
  assert(printChecks(pod.username, checks), 'Invalid pod config');
  return pod;
}

// Prints a message to the console
function print(message) {
  process.stdout.write(`${message}\n`);
}

// Prints a list of key/value checks to the console,
// returning whether all checks passed
function printChecks(name, checks) {
  const success = Object.values(checks).every(c => c);
  print(`\t${check(success)} ${name}\t ${
    Object.entries(checks).map(([key, value]) =>
      `${check(value)} ${key}`).join('\t')
  }`);
  return success;
}

// Returns a symbol for success or failure
function check(value) {
  return value ? '✅' : '❌';
}

// Reads and parses a JSON file from disk
async function readJson(path) {
  return JSON.parse(await readFile(path, 'utf-8'));
}
