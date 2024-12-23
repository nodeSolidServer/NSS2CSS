#!/usr/bin/env node
// #!/usr/bin/env node --no-warnings
// ©2023 Ruben Verborgh – MIT License

import assert from 'node:assert';
import { resolve } from 'node:path';
import { promisify } from 'node:util';
import * as childProcess from 'node:child_process';
import { lstat, readdir, readFile, writeFile } from 'node:fs/promises';
import fs from 'node:fs'

const execFile = promisify(childProcess.execFile);

const expectedArgs = {
  'nss/config.json': 'path to the NSS configuration file',
  'css/data': 'path to the CSS data folder',
  'https://css.pod/': 'URL to the running CSS server instance',
  'xxx@users.css.pod': 'e-mail pattern to generate CSS usernames',
  'step': 'number of accounts processed at each increment',
};

const passwordHashStart = '$2a$10$';

let cssFailedFetch = []
const invalidUsers = {
  notLowerCase: [],
  arobase: [],
  blank: [],
  nodata: [],
  dot: [],
  webid: [],
  profile: [],
  
}
let notLowerCase = []
let arobase = []
let blank = []
let nodata = []
let dot = []
let webid = []


main(...process.argv).catch(console.error);

// Starts migration with the command-line arguments
async function main(bin, script, ...args) {
  // if (args.length === 4) args[4] = ''
  if (args.length < Object.keys(expectedArgs).length-1) {
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
async function copyNssPodsToCSS(nssConfigPath, cssDataPath, cssUrl, emailPattern, step) {
  print('1️⃣  NSS: Read pod configurations from disk');
  const nss = await readNssConfig(nssConfigPath);
  const cssHost = (new URL(cssUrl)).host
  const nssHost = nss.serverUri.host
  const userFiles = (await readdir(nss.usersPath)).map(f => resolve(nss.usersPath, f));
  /* const userFiles = [
    resolve(nss.usersPath, '_key_bourgeoa.solidcommunity.net%2Fprofile%2Fcard%23me.json'),
    resolve(nss.usersPath, '_key_solidos.solidcommunity.net%2Fprofile%2Fcard%23me.json'),
    resolve(nss.usersPath, '_key_solidproject.solidcommunity.net%2Fprofile%2Fcard%23me.json'),
    resolve(nss.usersPath, '_key_jeff-zucker.solidcommunity.net%2Fprofile%2Fcard%23me.json'),
    resolve(nss.usersPath, '_key_timbl.solidcommunity.net%2Fprofile%2Fcard%23me.json'),
    resolve(nss.usersPath, '_key_michielbdjong.solidcommunity.net%2Fprofile%2Fcard%23me.json'),
    resolve(nss.usersPath, '_key_jeswr.solidcommunity.net%2Fprofile%2Fcard%23me.json'),
    resolve(nss.usersPath, '_key_cxres.solidcommunity.net%2Fprofile%2Fcard%23me.json')
  ] */
  const userPods = await asyncMap(readPodConfig, userFiles, nss);
  print('userPods ' + userPods.length)
  const userPodsLength = userPods.length
  /* while(userPods.length) {
    step = (step && (step < userPods.length)) ? step : userPods.length
    const pods = userPods.splice(0, step) */
  step = (step && (step < userPods.length)) ? step : userPods.length
  const chunks = userPods.chunk(step)
  // for (pods in chunks) {
  var remaining = userPods.length
  var accountsLength = 0
  /* for (let i = 0; i < chunks.length; i+=1) { // 2; i+=1) {
    const pods = chunks[i]
    // print(`\nprocessing ${step} accounts from remaining ${userPods.length+Number(step)}/${userPodsLength}\n`)
    print(`\nprocessing ${pods.length} accounts from remaining ${remaining}/${userPodsLength}\n`)
    remaining -= pods.length
    print(`2️⃣  CSS: Create ${pods.length} accounts with pods via HTTP`);
    const { account: { create } } = await getAccountControls(cssUrl);
    const emailDomain = emailPattern.replace(/.*@+/, '');
    const accounts = await asyncMap(createAccount, pods, create, emailDomain);

    print(`3️⃣  CSS: Update ${accounts.length} accounts on disk`);
    await asyncMap(updateAccount, accounts, resolve(cssDataPath, 'www/.internal'), nss.origin);

    print(`4️⃣  CSS: Copy ${accounts.length} pods contents on disk`);
    await asyncMap(copyPodFiles, accounts, nss.hostname, nss.dataPath, cssDataPath);

    print(`5️⃣  CSS: Update ${accounts.length} pods : replace WebID oidcIssuer`);
    const nssUrl = nss.serverUri.toString()
    print('nss ' + nss.serverUri + ' => css ' + cssUrl)
    await asyncMap(updateOidcIssuer, accounts, cssDataPath, nssUrl, cssUrl);

    print(`6️⃣  CSS: Update ${accounts.length} pods : replace defaultForNew on folders/.acl`);
    await asyncMap(updateAclDefault, accounts, cssDataPath)

    print(`7️⃣  CSS: Update ${accounts.length} pods : replace links on files content`);
    if (cssHost === nssHost) {
      print('OK, nothing to replace')
    } else {
      print(nssHost + ' ==> ' + cssHost)
      await asyncMap(updatePodLink, accounts, nssHost, cssHost, cssDataPath)
    }

    print(`8️⃣  CSS: Check ${accounts.length} pods for known resources`);
    await asyncMap(testPod, accounts, cssUrl);

    accountsLength += accounts.length
  } */
  print('NSS userFiles ' + userFiles.length)
  print('\ninvalid pods ' +
  '\n\tusername with dot ' + invalidUsers.dot.length +
  '\n\tnodata folder ' + invalidUsers.nodata.length +
  '\n\tother can\'access profile ' + invalidUsers.profile.length +
  '\n\tother can\'access WebID ' + invalidUsers.webid.length +
  '\n\tusername with arobase ' + invalidUsers.arobase.length +
  '\n\tusername with blank ' + invalidUsers.blank.length +
  '\n\tusername with uppercase letter ' + invalidUsers.notLowerCase.length +

  '\n\nvalid NSS pods ' + userPodsLength +
  '\n\ncreated CSS pods ' + accountsLength +
  '\n\nfailed CSS pod fetch ' + cssFailedFetch.length
  )
  print(cssFailedFetch)
}

// Reads the configuration of an NSS instance
async function readNssConfig(configPath) {
  assert.match(configPath, /config\.json$/, 'Invalid NSS config.json');
  const configFolder = resolve(configPath, '../');
  const config = await readJson(configPath);
  const serverUri = new URL(config.serverUri)
  return { // todo remove host and hostname
    serverUri: serverUri,
    host: serverUri.host,
    hostname: serverUri.hostname,
    dataPath: resolve(configFolder, config.root),
    usersPath: resolve(configFolder, config.dbPath, 'oidc/users/users/'),
  };
}

// Reads the configuration of a single pod from the NSS database
async function readPodConfig(configFile, nss) {
  const pod = await readJson(configFile);
  // if (pod?.username) pod.username = pod.username.toLowerCase()
  const checks = {
    username: !!pod.username,
    password: (pod.hashedPassword || '').startsWith(passwordHashStart),
    webId: !!pod.webId,
    pod: true,
  };
  const nssPodLocation = resolve(nss.dataPath, `${pod.username}.${nss.serverUri.hostname}`)
  try {
    // if (!checks.username && !checks.password && !pod.webId) checks.pod = false //throw new Error('undefined')
    if (pod.username.includes('.')) { invalidUsers.dot.push(pod.username); checks.pod = false } // throw new Error('dot') }
    else if (!fs.existsSync(nssPodLocation)) { invalidUsers.nodata.push(pod.username); checks.pod = false } // throw new Error('no data') }
    else if (!fs.existsSync(resolve(nssPodLocation, 'profile/card$.ttl'))) { invalidUsers.profile.push(pod.username); checks.pod = false } // throw new Error('webid') }
    else if (pod.username.includes('@')) { invalidUsers.arobase.push(pod.username); checks.pod = false } // throw new Error('arobase') }
    else if (pod.username.includes(' ')) { invalidUsers.blank.push(pod.username); checks.pod = false } // throw new Error('blank') }
    else if (!isLowerCase(pod.username)) { invalidUsers.notLowerCase.push(pod.username); checks.pod = false } // throw new Error('not lowercase') }
    else { await localFetch(new URL('/profile/card#me', nss.serverUri)) }
  } catch { invalidUsers.webid.push(pod.username); checks.pod = false }
  assert(printChecks(pod.username, checks), 'Invalid pod config');
  return pod;
}

// Creates a CSS account with a login and pod
async function createAccount(pod, creationUrl, emailDomain) {
  const { username, webId, hashedPassword } = pod;
  const checks = { account: false, login: false, pod: false };

  try {
    // Create and obtain a new empty account
    const { authorization } = await cssApiPost(creationUrl);
    const { controls } = await cssApiGet(creationUrl, authorization);
    const [, id] = /\/account\/([^/]+)\//.exec(controls.account.webId);
    checks.account = true;

    // Create a login to the account with a temporary password
    const password = generateRandomPassword();
    // We have to generate a new e-mail address per pod,
    // since NSS does not perform e-mail validation on sign-up.
    // As such, there exists a security risk in which
    // an attacker registers a bogus pod with someone else's e-mail,
    // in an attempt to gain access to all pods under that e-mail.
    const email = `${username}@${emailDomain}`;
    await cssApiPost(controls.password.create, { email, password }, authorization);
    checks.login = true;

    // Create a pod under the account
    await cssApiPost(controls.account.pod, { name: username }, authorization);
    checks.pod = true;
    // print('webId ' + webId)
    return { id, username, email, webId, hashedPassword };
  }
  finally {
    assert(printChecks(username, checks), 'Could not create account');
  }
}

// Updates the password and WebID in the account file
async function updateAccount(account, internalPath, nssOrigin) {
  const checks = { read: false, password: false, webId: false, write: false };
  try {
    // Read the account file from disk
    const accountFile = resolve(internalPath, `accounts/data/${account.id}$.json`);
    const accountConfig = await readJson(accountFile);
    checks.read = true;

    // Update the password section
    const passwordSections = Object.values(accountConfig['payload']['**password**']);
    assert.equal(passwordSections.length, 1);
    assert(account.hashedPassword.startsWith(passwordHashStart));
    assert(passwordSections[0].password.startsWith(passwordHashStart));
    passwordSections[0].password = account.hashedPassword;
    checks.password = true;

    // Update the WebID section
    if (account.webId) {
      const webIdSections = Object.values(accountConfig['payload']['**webIdLink**']);
      assert.equal(webIdSections.length, 1);
      assert(webIdSections[0].webId.startsWith('http'));
      assert(account.webId.startsWith('http'));
      // External WebID in NSS
      if (!account.webId.startsWith(nssOrigin)) {
        print('external webIdLink ' + webIdSections[0].webId)
        webIdSections[0].webId = account.webId;
      }
    }
    checks.webId = true;

    // Write the updated account configuration
    await writeJson(accountFile, accountConfig);
    checks.write = true;
  }
  finally {
    assert(printChecks(account.username, checks), 'Password update failed');
  }
}

// Copies the contents of the NSS pod to CSS via disk
async function copyPodFiles({ username }, hostname, nssDataPath, cssDataPath) {
  const checks = { clear: false, copy: false };
  const source = resolve(nssDataPath, `${username}.${hostname}`);
  const destination = resolve(cssDataPath, username);
  try {
    // Check that source and destination are folders
    assert((await lstat(source)).isDirectory(), 'Invalid source');
    // assert((await lstat(destination)).isDirectory(), 'Invalid destination');

    // Remove existing pod contents from the destination
    try {
      const stats = await lstat(destination)
      if (stats.isDirectory()) { await execFile('rm', ['-r', '--', destination]) }
    } catch (err) {}
    checks.clear = true

    // Copy new contents from the source to the destination
    await execFile('cp', ['-a', '--', source, destination]);
    checks.copy = true;

  }
  catch (err)
  {
    print(err)
  }
  finally {
    assert(printChecks(username, checks), 'Pod copy failed');
  }
}

// for CSS update oidcIssuer in webID document to cssUrl with '/'
// this allow migration to different port
async function updateOidcIssuer ({ username }, cssDataPath, nssUrl, cssUrl) {
  const checks = { oidcIssuer: false };
  const path = resolve(cssDataPath, username, 'profile/card$.ttl')
  try {
    var profile = (await readFile(path, 'utf8')).toString()
    var newProfile = ''
    const split1 = `:oidcIssuer <${nssUrl.slice(0, -1)}>` // .toString()
    const split2 = `oidcIssuer> <${nssUrl.slice(0, -1)}>` // .toString()

    if (profile.match(split1)) {
      newProfile = profile.split(split1).join(`:oidcIssuer <${cssUrl}>`)
    } else if (profile.match(split2)) {
      newProfile = profile.split(split2).join(`oidcIssuer> <${cssUrl}>`)
    } else { new Error('oidcIssuer not updated for podname : ' + username) }
    await writeFile(path, newProfile)
    checks.oidcIssuer = true
  }
  catch (err) {
    print(err)
  }
  finally {
    assert(printChecks(username, checks), 'oidcIssuer update failed');
  }
}

// for CSS replace deprecated acl:defaultForNew by acl:default in folders/.acl
async function updateAclDefault ({ username }, cssDataPath) {
  // const checks = { default: false };
  const pathToPod = resolve(cssDataPath, username)
  const source = 'acl:defaultForNew'
  const target = 'acl:default'
  const aclFile = '.acl'
  let count = 0

  try {
    // recursively replace string in folder/.acl
    await fromDir(pathToPod, aclFile, async function(filename) {
      const content = (await readFile(filename)).toString()
      const patt = new RegExp(source)
      if (patt.test(content)) {
        count += 1
        // update file
        const newContent = content.replace(new RegExp(source, 'g'), target)
        await writeFile(filename, newContent)
      }
    })
  }
  finally {
    // assert(print(`\t${username}\t${count}`), 'acl:default update failed');
  }
}

// for CSS replace deprecated acl:defaultForNew by acl:default in folders/.acl
async function updatePodLink ({ username }, nssHost, cssHost, cssDataPath) {
  // const checks = { default: false };
  const pathToPod = resolve(cssDataPath, username)
  const source = nssHost
  const target = cssHost
  const filter = ['.acl', '.meta', '.ttl']

  try {
    // recursively replace string in folder/.acl
    var count = 0
    // filter.map( async ext =>
    for (const i in filter) {
      const ext = filter[i]
      await fromDir(pathToPod, ext, async function(filename) {
        // const filename = resolve(pathToPod, ext) alain
        // print(filename) alain
        const content = (await readFile(filename)).toString()
        const patt = new RegExp(escapeStringRegExp(source)) // some username's contain .+ char
        if (patt.test(content)) {
          count += 1
          // print(count + '  ' + filename)
          // update file
          const newContent = rename(content, source, target)
          await writeFile(filename, newContent)
        }
      })
    }
    // print(count)
  }
  catch (err) { print(err) }
  finally {
    // assert(print(`\t${username}\t${count}`), 'acl:default update failed');
  }
}

// parse recursively all files matching filter and apply callback
// filter is .acl, .meta, .ttl
async function fromDir(startPath, filter, callback) {
  /* if (!fs.existsSync(startPath)) {
      console.log("no dir ",startPath)
      return
  } */
  var files = await readdir(startPath)
  for (var i = 0; i < files.length; i++) {
      var filename = resolve(startPath, files[i])
      var stat = await lstat(filename)
      if (stat.isDirectory()) {
          fromDir(filename, filter, callback) //recurse
      }
      else if (filename.endsWith(filter)) callback(filename)
  }
}

// rename server links
function rename (content, source, target) {
  // alain TODO review delimiters to keep item[1] only
  const delimiters = [['<', '>'], ['<', '/']] // json/jsonld , ['""', '""'], ['"', '/']]
  delimiters.map( item => {
    content = content.split(`.${source}${item[1]}`).join(`.${target}${item[1]}`)
  })
  return content
}

// Tests the given pod by trying to access typical resources
async function testPod({ username }, cssUrl) {
  const checks = { publicProfile: false, privateInbox: false, robotsFile: false };

  // Create URL for pod
  const podUrl = new URL(cssUrl);
  podUrl.hostname = `${username}.${podUrl.hostname}`;
  try {
    // Check presence of resources available in typical NSS pods
    const profile = await localFetch(new URL('/profile/card', podUrl));
    checks.publicProfile = profile.status === 200;
    const inbox = await localFetch(new URL('/inbox/', podUrl));
    checks.privateInbox = (inbox.status === 401 || inbox.status === 201); // some accounts allow everybody
    const robotsFile = await localFetch(new URL('/robots.txt', podUrl))
    checks.robotsFile = (robotsFile.status === 401 || robotsFile.status === 201);
  } catch (err) {
    cssFailedFetch.push(podUrl)
  }
  finally {
    assert(printChecks(username, checks), 'Pod test failed');
  }
}

// Retrieves the CSS hypermedia controls for the account API
async function getAccountControls(cssUrl) {
  try {
    const body = await cssApiGet(new URL('.account/', cssUrl));
    // assert.equal(body.version, '0.5', 'Unsupported CSS account API');
    return body.controls;
  }
  catch (cause) {
    throw new Error(`Could not access CSS configuration at ${cssUrl}`, { cause });
  }
}

// Performs an HTTP GET on an authenticated CSS API
async function cssApiGet(url, authorization = '') {
  return cssApiFetch(url, {}, authorization);
}

// Performs an HTTP POST on an authenticated CSS API
async function cssApiPost(url, body = {}, authorization = '') {
  return cssApiFetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  }, authorization);
}

// Performs an HTTP request on an authenticated CSS API
async function cssApiFetch(url, options = {}, authorization = '') {
  const response = await fetch(url, {
    ...options,
    headers: {
      ...options.headers,
      accept: 'application/json',
      authorization: `CSS-Account-Token ${authorization}`,
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

// Fail-safe async version of map that ignores failures
async function asyncMap(func, items, ...params) {
  const results = [];
  for (const item of items) {
    try {
      results.push(await func(item, ...params));
    }
    catch { /* Ignore unsuccessful executions */ }
  }
  return results;
}

// Prints a message to the console
function print(message) {
  process.stdout.write(`${message}\n`);
}

// Prints a list of key/value checks to the console,
// returning whether all checks passed
function printChecks(name, checks) {
  const success = Object.values(checks).every(c => c);
  if (success) {
    const checksString = Object.entries(checks).map(([key, value]) => `${check(value)} ${key}`).join('\t')
    print(`\t${check(success)} ${name}\t ${checksString}`);
  }
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

// escape characters in regular expression
// https://stackoverflow.com/questions/874709/converting-user-input-string-to-regular-expression
function escapeStringRegExp(str) {
  const escapeString = /[|\\{}()[\]^$+*?.]/g;
  return str.replace(escapeString, '\\$&');
}

// chunk Array
Array.prototype.chunk = function(n) {
  if (!this.length) {
    return [];
  }
  return [this.slice(0, n)].concat(this.slice(n).chunk(n));
}

// isLowerCase
function isLowerCase(str) {
  return str === str.toLowerCase() &&
         str !== str.toUpperCase();
}

/*
// log append to file
(async () => {
  // using appendFile.
  const fsp = require('fs').promises;
  await fsp.appendFile(
    '/path/to/file', '\r\nHello world.'
  );
*/
