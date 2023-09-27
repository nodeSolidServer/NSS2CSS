#!/usr/bin/env node --no-warnings
import assert from 'node:assert';
import { resolve } from 'node:path';
import { promisify } from 'node:util';
import * as childProcess from 'node:child_process';
import { lstat, opendir, readFile, writeFile } from 'node:fs/promises';

const execFile = promisify(childProcess.execFile);

const expectedArgs = {
  'nss/config.json': 'path to the NSS configuration file',
  'css/data': 'path to the CSS data folder',
  'https://css.pod/': 'URL to the running CSS server instance',
  'xxx@users.css.pod': 'e-mail pattern to generate CSS usernames',
};

const passwordHashStart = '$2a$10$';

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
async function copyNssPodsToCSS(nssConfigPath, cssDataPath, cssUrl, emailPattern) {
  print('1️⃣  NSS: Read pod configurations from disk');
  const nss = await readNssConfig(nssConfigPath);
  const pods = await readPodConfigs(nss.dbPath);

  print(`2️⃣  CSS: Create ${pods.length} accounts with pods via HTTP`);
  const accounts = await createAccounts(pods, cssUrl, emailPattern);

  print(`3️⃣  CSS: Update ${Object.keys(accounts).length} passwords on disk`);
  await updatePasswords(accounts, cssDataPath);

  print(`4️⃣  CSS: Update ${Object.keys(accounts).length} WebIDs on disk`);
  await updateWebIds(accounts, cssDataPath);

  print(`5️⃣  CSS: Copy ${Object.keys(accounts).length} pod contents on disk`);
  await copyPods(accounts, nss.hostname, nss.dataPath, cssDataPath);

  print(`6️⃣  CSS: Check ${Object.keys(accounts).length} pods for known resources`);
  await testPods(accounts, cssUrl);
}

// Reads the configuration of an NSS instance
async function readNssConfig(configPath) {
  assert.match(configPath, /config\.json$/, 'Invalid NSS config.json');
  const configFolder = resolve(configPath, '../');
  const config = await readJson(configPath);
  return {
    dbPath: resolve(configFolder, config.dbPath),
    dataPath: resolve(configFolder, config.root),
    hostname: new URL(config.serverUri).hostname,
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
    password: (pod.hashedPassword || '').startsWith(passwordHashStart),
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
    const { resource, cookie: authToken } = await cssApiPost(creationUrl);
    const { controls } = await cssApiGet(resource, authToken);
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
    await cssApiPost(controls.password.create, { email, password }, authToken);
    checks.login = true;

    // Create a pod under the account
    await cssApiPost(controls.account.pod, { name }, authToken);
    checks.pod = true;

    return { id, email };
  }
  finally {
    assert(printChecks(name, checks), 'Could not create account');
  }
}

// Updates all passwords on the CSS login filesystem
async function updatePasswords(accounts, dataPath) {
  const loginsPath = resolve(dataPath, 'www/.internal/accounts/logins/password/');
  for await (const entry of await opendir(loginsPath)) {
    if (entry.isFile() && entry.name.endsWith('$.json')) {
      try {
        await updatePassword(accounts, resolve(loginsPath, entry.name));
      }
      catch { /* Skip unsuccessful updates */ }
    }
  }
}

// Updates the password in the login file
async function updatePassword(accounts, loginFile) {
  const login = await readJson(loginFile);
  const nssAccount = accounts[login.accountId];

  if (nssAccount) {
    const checks = { oldPassword: false, newPassword: true };
    try {
      checks.oldPassword = login.password.startsWith(passwordHashStart);
      if (checks.oldPassword) {
        // Replace the temporary password by the NSS password hash
        login.password = nssAccount.hashedPassword;
        await writeJson(loginFile, login);
        checks.newPassword = true;
      }
    }
    finally {
      assert(printChecks(nssAccount.username, checks), 'Password update failed');
    }
  }
}

// Updates all WebIDs on the CSS account data filesystem
async function updateWebIds(accounts, dataPath) {
  const accountsPath = resolve(dataPath, 'www/.internal/accounts/data/');
  for await (const entry of await opendir(accountsPath)) {
    if (entry.isFile() && entry.name.endsWith('$.json')) {
      try {
        await updateWebId(accounts, resolve(accountsPath, entry.name));
      }
      catch { /* Skip unsuccessful updates */ }
    }
  }
}

// Updates the WebID in the account file
async function updateWebId(accounts, accountFile) {
  const cssAccount = (await readJson(accountFile)).payload;
  const nssAccount = accounts[cssAccount.id];

  if (nssAccount) {
    const checks = { oldWebId: false, newWebId: true };
    try {
      // Read the temporary WebID
      const tmpWebIds = Object.keys(cssAccount.webIds);
      assert.equal(tmpWebIds.length, 1);
      const tmpWebId = tmpWebIds[0];
      assert.match(tmpWebId, /^http/);
      const webIdConfigUrl = cssAccount.webIds[tmpWebId];
      assert.match(webIdConfigUrl, /^http.*\/account\//);

      // Replace the temporary WebID by the desired WebID
      delete cssAccount.webIds[tmpWebId];
      checks.oldWebId = true;
      if (nssAccount.webId)
        cssAccount.webIds[nssAccount.webId] = webIdConfigUrl;
      await writeJson(accountFile, { payload: cssAccount });
      checks.newWebId = true;
    }
    finally {
      assert(printChecks(nssAccount.username, checks), 'WebID update failed');
    }
  }
}

// Copies the contents of all NSS pods to CSS via disk
async function copyPods(accounts, hostname, nssDataPath, cssDataPath) {
  for (const { username } of Object.values(accounts)) {
    try {
      await copyPod(username, hostname, nssDataPath, cssDataPath);
    }
    catch { /* Skip unsuccessful copies */ }
  }
}

// Copies the contents of the NSS pod to CSS via disk
async function copyPod(username, hostname, nssDataPath, cssDataPath) {
  const checks = { clear: false, copy: false };
  const source = resolve(nssDataPath, `${username}.${hostname}`);
  const destination = resolve(cssDataPath, username);
  try {
    // Check that source and destination are folders
    assert((await lstat(source)).isDirectory(), 'Invalid source');
    assert((await lstat(destination)).isDirectory(), 'Invalid destination');

    // Remove existing pod contents from the destination
    await execFile('rm', ['-r', '--', destination]);
    checks.clear = true;

    // Copy new contents from the source to the destination
    await execFile('cp', ['-a', '--', source, destination]);
    checks.copy = true;
  }
  finally {
    assert(printChecks(username, checks), 'Pod copy failed');
  }
}

// Tests for each pod whether it is accessible
async function testPods(accounts, cssUrl) {
  for (const { username } of Object.values(accounts)) {
    try {
      await testPod(username, cssUrl);
    }
    catch { /* Skip unsuccessful copies */ }
  }
}

// Tests the given pod by trying to access typical resources
async function testPod(username, cssUrl) {
  const checks = { publicProfile: false, privateInbox: false };

  // Create URL for pod
  const podUrl = new URL(cssUrl);
  podUrl.hostname = `${username}.${podUrl.hostname}`;

  try {
    // Check presence of resources available in typical NSS pods
    const profile = await localFetch(new URL('/profile/card', podUrl));
    checks.publicProfile = profile.status === 200;
    const inbox = await localFetch(new URL('/inbox/', podUrl));
    checks.privateInbox = inbox.status === 401;
  }
  finally {
    assert(printChecks(username, checks), 'Pod test failed');
  }
}

// Retrieves the CSS hypermedia controls for the account API
async function getAccountControls(cssUrl) {
  try {
    const body = await cssApiGet(new URL('.account/', cssUrl));
    assert.equal(body.version, '0.5', 'Unsupported CSS account API');
    return body.controls;
  }
  catch (cause) {
    throw new Error(`Could not access CSS configuration at ${cssUrl}`, { cause });
  }
}

// Performs an HTTP GET on an authenticated CSS API
async function cssApiGet(url, authToken = '') {
  return cssApiFetch(url, {}, authToken);
}

// Performs an HTTP POST on an authenticated CSS API
async function cssApiPost(url, body = {}, authToken = '') {
  return cssApiFetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  }, authToken);
}

// Performs an HTTP request on an authenticated CSS API
async function cssApiFetch(url, options = {}, authToken = '') {
  const response = await fetch(url, {
    ...options,
    headers: {
      ...options.headers,
      accept: 'application/json',
      authorization: `CSS-Account-Cookie ${authToken}`,
    },
  });
  const json = await response.json();
  if (response.status !== 200)
    throw new Error(json.message);
  return json;
}

// Fetches the resource with special DNS resolution for local names
function localFetch(url, init = {}) {
  url = new URL(url);

  // The `pod.localhost` pattern is common within NSS and CSS,
  // but Node.js does not resolve this well by default
  const host = url.host;
  if (url.hostname.endsWith('.localhost'))
    url.hostname = 'localhost';

  return fetch(url, { ...init, headers: { host } });
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

// Writes a JSON file to disk
async function writeJson(path, contents = {}) {
  await writeFile(path, JSON.stringify(contents));
}
