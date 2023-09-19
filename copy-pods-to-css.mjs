#!/usr/bin/env node --no-warnings
import assert from 'node:assert';
import { resolve } from 'node:path';
import { opendir, readFile } from 'node:fs/promises';

const expectedArgs = {
  'nss/config.json': 'path to the NSS configuration file',
  'https://css.pod/': 'URL to the running CSS server instance',
  'xxx@users.css.pod': 'e-mail pattern to generate CSS usernames',
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
async function copyNssPodsToCSS(nssConfigPath, cssUrl, emailPattern) {
  print('1️⃣  NSS: Read pod configurations from disk');
  const nss = await readNssConfig(nssConfigPath);
  const pods = await readPodConfigs(nss.dbPath);

  print(`2️⃣  CSS: Create ${pods.length} accounts with pods via HTTP`);
  const accounts = await createAccounts(pods, cssUrl, emailPattern);
  print(`Created ${Object.keys(accounts).length} accounts`);
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

// Creates a CSS account and pod for each of the NSS pods
async function createAccounts(pods, cssUrl, emailPattern) {
  const accounts = {};
  const emailDomain = emailPattern.replace(/.*@+/, '');
  const { account: { create } } = await getAccountControls(cssUrl);
  for (const pod of pods) {
    try {
      const account = await createAccount(create, pod.username, emailDomain);
      accounts[account.id] = { ...pod, ...account };
    }
    catch { /* Skip unsuccessful accounts */ }
  }
  return accounts;
}

// Creates a CSS account with a login and pod
async function createAccount(creationUrl, name, emailDomain) {
  const checks = { account: false, login: false, pod: false };

  try {
    // Create and obtain a new empty account
    const { resource, cookie } = await cssPost(creationUrl);
    const { controls } = await cssGet(resource, cookie);
    const [, id] = /account\/([^/]+)\/$/.exec(resource);
    checks.account = true;

    // Create a login to the account with a temporary password
    const password = generateRandomPassword();
    // We have to generate a new e-mail address per pod,
    // since NSS does not perform e-mail validation on sign-up.
    // As such, there exists a security risk in which
    // an attacker registers a bogus pod with someone else's e-mail,
    // in an attempt to gain access to all pods under that e-mail.
    const email = `${name}@${emailDomain}`;
    await cssPost(controls.password.create, { email, password }, cookie);
    checks.login = true;

    // Create a pod under the account
    await cssPost(controls.account.pod, { name }, cookie);
    checks.pod = true;

    return { id, email, cookie, controls };
  }
  finally {
    assert(printChecks(name, checks), 'Could not create account');
  }
}

// Retrieves the CSS hypermedia controls for the account API
async function getAccountControls(cssUrl) {
  try {
    const body = await cssGet(new URL('.account/', cssUrl));
    assert.equal(body.version, '0.5', 'Unsupported CSS account API');
    return body.controls;
  }
  catch (cause) {
    throw new Error(`Could not access CSS configuration at ${cssUrl}`, { cause });
  }
}

// Retrieves JSON from CSS via an authenticated HTTP request
async function cssGet(url, cookie = '') {
  return cssFetch(url, {}, cookie);
}

// Posts JSON to CSS via an authenticated HTTP request
async function cssPost(url, body = {}, cookie = '') {
  return cssFetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  }, cookie);
}

// Performs an authenticated HTTP request on CSS
async function cssFetch(url, options = {}, cookie = '') {
  const response = await fetch(url, {
    ...options,
    headers: {
      ...options.headers,
      accept: 'application/json',
      cookie: `css-account=${cookie}`,
    },
  });
  const json = await response.json();
  if (response.status !== 200)
    throw new Error(json.message);
  return json;
}

// Generates a random password
function generateRandomPassword(length = 32) {
  return new Array(length).fill(0).map(() =>
    String.fromCharCode(65 + Math.floor(58 * Math.random()))).join('');
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
