// Configuration
const NETWORK_NAME = '<Your network name>';
const REPORT_RECIPIENTS = "<Your list of email recipients>";
const HIGH_SEVERITY_PARENT_CATEGORIES = ['Sensitive', 'Security'];
const HIGH_SEVERITY_CHILDREN_CATEGORIES = ['Shopping', 'Uncategorized', 'Streaming Media', 'News and Media', 'Social Networking'];

// Globals
const TEMP_REPORT_FOLDER = 'Temporary Report Data';
const REPORTS_BACKUPS_FOLDER = 'Reports Backups';
const CONFIG_BACKUPS_FOLDER = 'Configuration Backups';
const REPORT_DATE_FILENAME = 'report_date.txt';
const CONFIRMED_SENT_FILENAME = 'confirmed_sent.txt';
const NETWORK_CONF_FILENAME = 'network.js';
const WEBFILTER_CONF_FILENAME = 'settings_5.js';

function sendReport() {
  const reportDate = checkSentAndInitialize();
  if(!reportDate) {
    return;
  }
  const [domainHitsData, rawData, searchData, tempUnblockedData, hostsByCategoryData] = getQueryData();
  const searchDataUniq = dedupeSearchData(searchData);
  const htmlReportData = [searchDataUniq, tempUnblockedData];
  emailReport(hostsByCategoryData, htmlReportData, domainHitsData, rawData, NETWORK_NAME + "Network Report for " + getHumanDate(reportDate));
}

function checkSentAndInitialize() {
  const reportFolder = getReportFolder();
  // Find the latest report contents date
  const latestReportFile = getLatestInFolder('Reports Backups', 'reports_csv');
  const latestReportDate = getDateFromFilename(latestReportFile);
  if(reportFolder) {
    const currentReportDate = new Date(findInReportsFolder(REPORT_DATE_FILENAME).getBlob().getDataAsString());
    const isReportNew = currentReportDate < latestReportDate;
    const foundSentFile = findInReportsFolder(CONFIRMED_SENT_FILENAME);
    if (isReportNew) {
      Logger.info("Report folder exists and it's an old date, so setup and send the report.");
      Logger.info(`Old date is ${currentReportDate}, but the newest report date is ${latestReportDate}`);
      cleanAndExtractFiles(latestReportFile, latestReportDate);
      return latestReportDate;
    } else if(!foundSentFile) {
      Logger.info("Report folder exists and it's current but there no sent confirmation, so use what we have and send the report");
      return currentReportDate;
    }
  } else {
    Logger.info("Report folder doesn't exist, so setup and send the report");
    cleanAndExtractFiles(latestReportFile, latestReportDate);
    return latestReportDate;
  }
  Logger.info("Report folder exists and there we've already sent the report. Great! Wait til tomorrow.");
  return false;
}

function cleanAndExtractFiles(latestReportFile, latestReportDate) {
  // Delete previous temporary folder(s)
  cleanTempFolder();
  const reportFolder = DriveApp.createFolder(TEMP_REPORT_FOLDER);
  reportFolder.createFile(REPORT_DATE_FILENAME, latestReportDate);
  const extractedConfigs = extractConfigs([NETWORK_CONF_FILENAME, WEBFILTER_CONF_FILENAME]);
  extractedConfigs.forEach(config => reportFolder.createFile(config));
  const reportLogs = Utilities.unzip(latestReportFile);
  const desiredLogs = ['http_query_events','http_events'];
  reportLogs
    .filter(csv => desiredLogs.some(nameInclude => csv.getName().includes(nameInclude)))
    .forEach(foundCsv => reportFolder.createFile(foundCsv));
}

function dedupeSearchData(searchData) {
  // Coloring a row
  // https://stackoverflow.com/questions/17367503/how-to-change-whole-row-color-in-google-script
  const ipNameMap = getNetworkNameMap(findInReportsFolder(NETWORK_CONF_FILENAME).getBlob());
  const searchEventsData = searchData.content.reduce((accumulator, [time_stamp, c_client_addr, hostname, provider, term]) => {
    const [lastItem] = accumulator.slice(-1);
    if (!lastItem || !(lastItem[1] === c_client_addr && lastItem[4] === term)) {
      accumulator.push([time_stamp, c_client_addr, hostname, provider, term]);
    }
    return accumulator;
  }, [])
  .map(([time_stamp, c_client_addr, hostname, site, term]) => {
    const humanDate = new Date(time_stamp).toLocaleTimeString();
    const machineName = ipNameMap[c_client_addr] || hostname;
    return [humanDate, machineName, site, term];
  });
  searchData.content = searchEventsData;
  return searchData;
}

function getQueryData() {
  let allDataContent = [];
  let hostDomainDetailsMap = {};
  let domainCategoryMap = {};
  const ipNameMap = getNetworkNameMap(findInReportsFolder(NETWORK_CONF_FILENAME).getBlob());
  const ruleMap = getRuleMappings(findInReportsFolder(WEBFILTER_CONF_FILENAME).getBlob());
  function getFilterReason(filter_type, ruleId) {
    const filterList = ruleMap[filter_type];
    if(filterList) {
      const filterReason = filterList[ruleId];
      if(filterReason) {
        return filterReason;
      }
    }
    return {name: 'Uncategorized'};
  }
  const queryDataFile = findInReportsFolder('http_events').getBlob().setName('http_events.csv');
  const searchDataRaw = [];
  const temporarilyUnblocked = new Set();
  const parseData = parseCsvRows(queryDataFile)
    parseData.content.forEach(([request_id, time_stamp, session_id, client_intf, server_intf, c_client_addr, s_client_addr, c_server_addr, s_server_addr, c_client_port, s_client_port, c_server_port, s_server_port, client_country, client_latitude, client_longitude, server_country, server_latitude, server_longitude, policy_id, username, hostname, method, uri, host, domain, referer, c2s_content_length, s2c_content_length, s2c_content_type, s2c_content_filename, ad_blocker_cookie_ident, ad_blocker_action, web_filter_reason, web_filter_category_id, web_filter_rule_id, web_filter_blocked, web_filter_flagged, virus_blocker_lite_clean, virus_blocker_lite_name, virus_blocker_clean, virus_blocker_name, threat_prevention_blocked, threat_prevention_flagged, threat_prevention_reason, threat_prevention_rule_id, threat_prevention_client_reputation, threat_prevention_client_categories, threat_prevention_server_reputation, threat_prevention_server_categories]) => {
      const machine = ipNameMap[c_client_addr] || hostname;
      domain = domain.startsWith('www.') ? domain.replace('www.', '') : domain;
      let rule = '';
      if(Number(web_filter_rule_id)) {
        const filterReason = getFilterReason(web_filter_reason, web_filter_rule_id);
        if(web_filter_reason === 'D' && filterReason.name) {
          rule = filterReason.name;
        } else if(filterReason.description) {
          rule = filterReason.description;
        }
      }

      // COMPILE SEARCH DATA
      [provider, searchTerm] = checkForSearchQuery(domain, uri);
      if(searchTerm) {
        searchDataRaw.push([time_stamp, c_client_addr, hostname, provider, searchTerm]);
      }

      // COMPILE SUMMARY DOMAIN DATA
      // Find the domain and add to the details for this domain
      const domainHitDetailsMap = hostDomainDetailsMap[machine] || {};
      const domainHitDetails = domainHitDetailsMap[domain] || {};
      domainHitDetails.hits = domainHitDetails.hits + 1 || 1;
      domainHitDetails.referred = referer ? (domainHitDetails.referred + 1 || 1) : (domainHitDetails.referred || 0);
      domainHitDetails.blocked = web_filter_blocked === 't' ? (domainHitDetails.blocked + 1 || 1) : (domainHitDetails.blocked || 0);
      // Build our map back again
      domainHitDetailsMap[domain] = domainHitDetails;
      hostDomainDetailsMap[machine] = domainHitDetailsMap;
      
      const isDomainCategorized = Boolean(Number(domainCategoryMap[domain]));
      const isGoodCategory = Boolean(Number(web_filter_category_id));
      if(!isDomainCategorized) {
        domainCategoryMap[domain] = isGoodCategory ? web_filter_category_id : "0";
      }

      // COMPILE TEMPORARY UNBLOCKED
      if(web_filter_reason === 'B') {
        temporarilyUnblocked.add(domain);
      }

      // COMPILE ALL DATA
      const blocked = web_filter_blocked === 't' ? true : false;
      allDataContent.push([time_stamp, machine, domain + uri, referer, getWebFilterReason(web_filter_reason), rule, blocked])
    });
  Object.entries(domainCategoryMap).forEach(([domain, webCatId]) => {
    if(webCatId === "0") {
      domainCategoryMap[domain] = chooseBestForUncategorized(domain, domainCategoryMap);
    }
  });
  let domainHitData = [];
  let hostsByCategoryMap = {}
  Object.entries(hostDomainDetailsMap)
    .forEach(([machine, domainHits]) => {
      Object.entries(domainHits)
        .forEach(([domain, details]) => {
          const webCatId = domainCategoryMap[domain];
          const filterReason = getFilterReason('D', webCatId).name;
          domainHitData.push([machine, domain, filterReason, details.blocked, details.referred, details.hits]);

          // COMPILE HOSTS BY CATEGORY
          hostsByCategoryMap[webCatId] = hostsByCategoryMap[webCatId] || {};
          hostsByCategoryMap[webCatId][machine] = hostsByCategoryMap[webCatId][machine] || {};
          const rootDomain = getRootDomain(domain);
          const domainHitDetails = hostsByCategoryMap[webCatId][machine][rootDomain] || {};
          domainHitDetails.hits = domainHitDetails.hits + details.hits || details.hits;
          domainHitDetails.referred = domainHitDetails.referred + details.referred || details.referred;
          domainHitDetails.blocked = domainHitDetails.blocked + details.blocked || details.blocked;
          // Build our map back again
          hostsByCategoryMap[webCatId][machine][rootDomain] = domainHitDetails;
        });
    });
  const hostsByCategoryData = Object.entries(hostsByCategoryMap).map(([webCatId, machineAndDomains]) => {
    const categoryDetails = getFilterReason('D', webCatId);
    let severity = 0;
    if((HIGH_SEVERITY_PARENT_CATEGORIES.includes(categoryDetails.category) 
        || HIGH_SEVERITY_CHILDREN_CATEGORIES.includes(categoryDetails.name))
        && categoryDetails.name !== 'Religion') {
      severity = 2;
    } else if(categoryDetails.blocked || ['Society', 'Personal sites and Blogs'].includes(categoryDetails.name)) {
      severity = 1
    }
    return [severity, categoryDetails.name, machineAndDomains];
  });
  hostsByCategoryData.sort(([prevSeverity, prevCat, prevMachines], [severity, cat, machines]) => {
    return severity - prevSeverity || prevCat.localeCompare(cat)});
  domainHitData.sort(([prevMachine, prevDomain, prevCat, prevDetails], [machine, domain, cat, details]) => {
    return prevMachine.localeCompare(machine) || prevCat.localeCompare(cat) || prevDomain.localeCompare(domain)});
  const domainHitHeaders = ['Host', 'Domain', 'Category', 'Blocked', 'Referred', 'Hits'];
  const allDataHeaders = ['Timestamp', 'Host', 'URL', 'Referer', 'Filter Reason', 'Rule', 'Blocked'];
  const hostsByCategoryHeaders = ['Category', 'Hosts'];

  const searchHeaders = ['Date', 'Host', 'Site', 'Search'];
  return [new Data(domainHitHeaders, domainHitData, "Summary"), 
          new Data(allDataHeaders, allDataContent, "Data"),
          new Data(searchHeaders, searchDataRaw, "Search Report"),
          new Data(['Site'], [...temporarilyUnblocked].map(domain => [domain]), "Temporarily Unblocked"),
          new Data(hostsByCategoryHeaders, hostsByCategoryData, "Hosts by Category")];
}

function emailReport(hostsByCategory, dataList, domainHitsData, rawData, subject) {
  let email = {
    name: NETWORK_NAME + "Untangle",
    to: REPORT_RECIPIENTS,
    subject: subject,
    attachments: [convertToExcel(subject, domainHitsData, rawData)],
    htmlBody: convertToHtml(hostsByCategory, dataList)
  };
  
  MailApp.sendEmail(email);
  Logger.log("Sent \"%s\"", subject);

  getReportFolder().createFile(CONFIRMED_SENT_FILENAME, "");
}

function removeOldFiles() {
  let oldDate = new Date();
  oldDate.setMonth(oldDate.getMonth() - 3);
  const expirationDate = oldDate.toISOString().split('T')[0];
  [REPORTS_BACKUPS_FOLDER, CONFIG_BACKUPS_FOLDER].forEach(folderName => {
    const foundFolders = DriveApp.getFoldersByName(folderName);
    while(foundFolders.hasNext()) {
      const foundFolder = foundFolders.next();
      const oldFiles = foundFolder.searchFiles(`modifiedDate < "${expirationDate}"`);
      while(oldFiles.hasNext()) {
        const oldFile = oldFiles.next();
        oldFile.setTrashed(true);
      }
    }
  });
  GmailApp.search(`in:sent before:${oldDate.toISOString().split('T')[0]}`).forEach(sentEmail => sentEmail.moveToTrash());
}


// --------------- UTILITIES -----------------
function searchTools() {
  const SEARCH_DEFINITIONS = [
    new SearchDefinition('amazon\\.', 'Amazon', '.*amazon\\.[a-z]+(\\.[a-z]+)?/.*(\\?|&)k(eywords)?=(?<query>[^&]+).*'),
    new SearchDefinition('duckduckgo\\.', 'DuckDuckGo', '.*duckduckgo\\.[a-z]+(\\.[a-z]+)?/(?!ac/).*(\\?|&)q=(?<query>[^&]+).*'),
    new SearchDefinition('ebay\\.', 'eBay', '.*ebay\\.[a-z]+(\\.[a-z]+)?/.*(\\?|&)_nkw=(?<query>[^&]+).*'),
    new SearchDefinition('google\\.', 'Google', '.*google\\.[a-z]+(\\.[a-z]+)?/(?!complete/)search.*(\\?|&)q=(?<query>[^&]+).*'),
    new SearchDefinition('google\\.', 'Google', '.*google\\.[a-z]+(\\.[a-z]+)?/gen_204(\\?|&)oq=(?<query>[^&]+).*'),
    new SearchDefinition('kidzsearch\\.', 'KidzSearch', '.*kidzsearch\\.[a-z]+(\\.[a-z]+)?/.*(\\?|&)q=(?<query>[^&]+).*'),
    new SearchDefinition('wikipedia\\.', 'Wikipedia', '.*wikipedia\\.[a-z]+(\\.[a-z]+)?/.*(\\?|&)search=(?<query>[^&]+).*'),
    // new SearchDefinition('ask', 'Ask', '.*ask\\.[a-z]+(\\.[a-z]+)?/web.*(\\?|&)q=(?<query>[^&]+).*'),
    // new SearchDefinition('bing', 'Bing', '.*bing\\.[a-z]+(\\.[a-z]+)?/search.*(\\?|&)q=(?<query>[^&]+).*'),
    // new SearchDefinition('yahoo', 'Yahoo', '.*yahoo\\.[a-z]+(\\.[a-z]+)?/search.*(\\?|&)p=(?<query>[^&]+).*'),
  ];
  const SEARCH_HOSTNAME_TESTS = new RegExp(`(${[...new Set(SEARCH_DEFINITIONS.map(searchDef => searchDef.host))].join('|')})`);
  return [SEARCH_DEFINITIONS, SEARCH_HOSTNAME_TESTS];
}

class Data {
  constructor(headers, content, name) {
    this.headers = headers;
    this.content = content;
    this.name = name;
  }
}

class SearchDefinition {
  constructor(host, provider, pattern) {
    this.host = host;
    this.provider = provider;
    this.pattern = new RegExp(pattern);
  }

  findSearch(url) {
    const found = url.match(this.pattern);
    if(found?.groups?.query) {
      return [this.provider, decodeURIComponent(found.groups.query.replaceAll('+', ' '))];
    }
    return [undefined, undefined];
  }
}

function testSearchQueries() {
  const urls = ['google.com/complete/search?cp=9&client=psy-ab&xssi=&output=json&q=py&jsonp=acp_new&_=12756893'];
  const urlsParsed = urls.map(url => {
    const [host, uri] = url.split(/_(.+)/)
    return {host, uri}
  });
  urlsParsed.forEach(fullUrl => Logger.log(checkForSearchQuery(fullUrl)));
}

// Search for searches
function checkForSearchQuery(host, uri) {
  const [SEARCH_DEFINITIONS, SEARCH_HOSTNAME_TESTS] = searchTools();
  let searchTerm;
  if(SEARCH_HOSTNAME_TESTS.test(host)) {
    for(const searchDef of SEARCH_DEFINITIONS) {
      [provider, searchTerm] = searchDef.findSearch(host + uri);
      if(searchTerm) {
        return [provider, searchTerm];
      };
    }
  }
  return [undefined, undefined];
}

function cleanTempFolder() {
  const a = DriveApp.getFolders();
  while(a.hasNext()) {
    const rootFolder = a.next();
    if(rootFolder.getName().startsWith(TEMP_REPORT_FOLDER)) {
      Logger.log("Removing prior temp folder %s", rootFolder);
      rootFolder.setTrashed(true);
    }
  }
}

function findInReportsFolder(namePart) {
  const reportFolder = getReportFolder();
  const files = reportFolder.getFiles();
  while(files.hasNext()) {
    const file = files.next();
    if(file.getName().includes(namePart)) {
      return file;
    } 
  }
  Logger.log("No filename containing " + namePart + " exists in the report folder");
}

function getReportFolder() {
  const reportFolders = DriveApp.getFoldersByName(TEMP_REPORT_FOLDER);
  if(reportFolders.hasNext()) {
    return reportFolders.next();
  }
  Logger.log("No report folder " + TEMP_REPORT_FOLDER + " exists in the root drive folder!");
}

function createSpreadsheetInFolder(spreadsheetName, folder) {
    const spreadsheet = SpreadsheetApp.create(spreadsheetName);
    var newfile = DriveApp.getFileById(spreadsheet.getId());
    newfile.moveTo(folder)
    return spreadsheet;
}

function getDateFromFilename(fileName) {
  return new Date(fileName.getName().split('-')[2].split('.')[0].split('_').join('/'));
}

function getHumanDate(dateStr) {
  // From format like 2021/05/26
  return new Date(dateStr).toDateString();
}

const MS_PER_DAY = 1000 * 60 * 60 * 24;

function dateDiffInDays(a, b) {
  // a and b are Date objects
  // Discard the time and time-zone information.
  const utc1 = Date.UTC(a.getFullYear(), a.getMonth(), a.getDate());
  const utc2 = Date.UTC(b.getFullYear(), b.getMonth(), b.getDate());

  return Math.floor((utc1 - utc2) / MS_PER_DAY);
}

function inverse(obj){
  let retobj = {};
  for(let key in obj){
    retobj[obj[key]] = key;
  }
  return retobj;
}

function getLatestInFolder(folderName, nameContains) {
  const folders = DriveApp.getFoldersByName(folderName);
  while (folders.hasNext()) {
    const reportsFolder = folders.next();
    const reportsFiles = reportsFolder.getFiles();
    let latestFile = undefined;
    while (reportsFiles.hasNext()) {
      let reportFile = reportsFiles.next();
      if(reportFile.getName().includes(nameContains)) {
        if(!latestFile){
          latestFile = reportFile;
        }
        if(reportFile.getDateCreated().getTime() > latestFile.getDateCreated().getTime()) {
          latestFile = reportFile;
        }
      }
    }
    if(latestFile) {
      Logger.log('Latest log file found: %s, created: %s', latestFile.getName(), latestFile.getDateCreated());
      return latestFile;
    }
  }
  throw Error('No ' + nameContains + ' files exist in the Untangle backup folder');
}

function parseCsvRows(csvBlob) {
  const zip = (a, b) => a.map((k, i) => [k, b[i]]);
  // Google app scripts parse CSV does not work on properly formatted double-quoted strings containing things like , and \n
  const sanitizedCsv = csvBlob.getDataAsString().replace(/'"[^"]+"/g, match => match.replace(/,/g, ';'));
  const csvRows = Utilities.parseCsv(sanitizedCsv);
  headers = csvRows.shift();
  return new Data(headers, csvRows);
}

function extractConfigs(configNames) {
  const latestConfTarGz = getLatestInFolder('Configuration Backups', 'configuration_backup');

  const latestNestedFilesTarGz = getFilesInTarGz(latestConfTarGz).find(fileRef => fileRef.file.getName().includes('files')).file;
  const configFiles = getFilesInTarGz(latestNestedFilesTarGz);
  return configNames.map(configName => configFiles.find(fileRef => fileRef.file.getName().includes(configName)).file);
}

function getNetworkNameMap(networkConfig) {
  const dhcpDefs = JSON.parse(networkConfig.getDataAsString());
  return Object.fromEntries(dhcpDefs.staticDhcpEntries.list.map(e => [e.address, e.description]));
}

function getRuleMappings(ruleConfig) {
  const ruleDefs = JSON.parse(ruleConfig.getDataAsString());
  let ruleMappings = {};
  Object.entries(WEB_REASONS).forEach(([reasonKey, {reason, configId}]) => {
    if(configId) {
      ruleMappings[reasonKey] = Object.fromEntries(ruleDefs[configId].list.map((rule, i) => [rule.id || i, {blocked: rule.blocked, description: rule.description, category: rule.category, name: rule.name}]));
    }
  });
  return ruleMappings;
}

function chooseBestForUncategorized(domain, domainCategoryMap) {
  let bestWebCategory = "0";
  if(!Number(domainCategoryMap[domain])) {
    const splitDomain = domain.split('.');
    if(splitDomain.length > 2) {
      for(let x = 1; x <= splitDomain.length - 2; x++) {
        const higherLevelDomain = splitDomain.slice(x).join(".");
        if(Number(domainCategoryMap[higherLevelDomain])) {
          bestWebCategory = domainCategoryMap[higherLevelDomain];
        }
      }
    }
  }
  return bestWebCategory;
}

function getRootDomain(domain) {
  const splitDomain = domain.split('.');
  if(splitDomain.length > 2) {
    const top2 = splitDomain.slice(-2).join('.');
    if(top2.length < 11) {
      return splitDomain.slice(-3).join('.');
    } else {
      return top2;
    }
  }
  return domain;
}

const hashCode = str => {
  var hash = 0, i, chr;
  if (str.length === 0) return hash;
  for (i = 0; i < str.length; i++) {
    chr   = str.charCodeAt(i);
    hash  = ((hash << 5) - hash) + chr;
    hash |= 0; // Convert to 32bit integer
  }
  return hash;
};
const hex = d => Number(d).toString(16).padStart(2, '0');
const getColorHex = str => '#' + hex(hashCode(str) >> 8).padStart(6, 0);
const getPastelHsl = str => {
  const hash = Math.abs(hashCode(str));
  const hue = hash % 360;
  const saturation = 45 + (hash % 50);
  const lightness = 75 + (hash % 20);
  return `hsl(${hue}, ${saturation}%, ${lightness}%)`;
};

// --------------- Spreadsheet Helpers ---------------

function addSheetToSpreadsheet(spreadSheet, sheetData, autosize) {
  let allData = [];
  allData.push(sheetData.headers);
  allData = allData.concat(sheetData.content);
  const rowCount = allData.length;
  const columnCount = allData[0].length;
  const newSheet = insertSheet(spreadSheet, sheetData.name, 0, rowCount, columnCount, "");
  newSheet.getRange(1, 1, rowCount, columnCount).setValues(allData);
  if(autosize) {
    newSheet.autoResizeColumns(1, columnCount);
  }
  newSheet.setFrozenRows(1);
}

function convertToExcel(subject, domainHitsData, rawData) {
  // Use SpreadSheetApp to make this an Excel, see https://gist.github.com/Spencer-Easton/78f9867a691e549c9c70
  const reportFolderId = getReportFolder();
  const reportSheet = createSpreadsheetInFolder(subject, reportFolderId);

  addSheetToSpreadsheet(reportSheet, domainHitsData, true);
  addSheetToSpreadsheet(reportSheet, rawData, false);
  // Remove the default sheet
  reportSheet.deleteSheet(reportSheet.getSheetByName("Sheet1"));
  SpreadsheetApp.flush();
  const url = "https://docs.google.com/feeds/download/spreadsheets/Export?key=" + reportSheet.getId() + "&exportFormat=xlsx";
  var params = {
    method      : "get",
    headers     : {"Authorization": "Bearer " + ScriptApp.getOAuthToken()},
    muteHttpExceptions: true
  };
  return UrlFetchApp.fetch(url, params).getBlob().setName(reportSheet.getName() + ".xlsx");      
}

SEVERITY_COLORS = {
  0: 'green',
  1: 'yellow',
  2: 'red',
};

function convertToHtml(hostsByCategory, dataList) {
  let reportTemplate = HtmlService.createTemplateFromFile('TabularReportTemplate');
  reportTemplate.dataList = dataList;
  reportTemplate.hostsByCategory = hostsByCategory;
  reportTemplate.getPastelHsl = getPastelHsl;
  reportTemplate.severityColors = SEVERITY_COLORS;
  return reportTemplate.evaluate().getContent();
}

/**
 * From https://stackoverflow.com/questions/33787057/how-to-set-a-sheets-number-of-rows-and-columns-at-creation-time-and-a-word-ab
 * 
 * Wrapper for Spreadsheet.insertSheet() method to support customization.
 * All parameters are optional & positional.
 *
 * @param {Spreadsheet} ss        Spreadsheet to start with
 * @param {String}  sheetName     Name of new sheet (defaults to "Sheet #")
 * @param {Number}  sheetIndex    Position for new sheet (default 0 means "end")
 * @param {Number}  rows          Vertical dimension of new sheet (default 0 means "system default", 1000)
 * @param {Number}  columns       Horizontal dimension of new sheet (default 0 means "system default", 26)
 * @param {String}  template      Name of existing sheet to copy (default "" means none)
 *
 * @returns {Sheet}               Sheet object for chaining.
 */
function insertSheet( ss, sheetName, sheetIndex, rows, columns, template ) {
  // Check parameters, set defaults
  var numSheets = ss.getSheets().length;
  sheetIndex = sheetIndex || (numSheets + 1);
  sheetName = sheetName || "Sheet " + sheetIndex;
  var options = template ? { 'template' : ss.getSheetByName(template) } : {};
  // Will throw an exception if sheetName already exists
  var newSheet = ss.insertSheet(sheetName, sheetIndex, options);
  if (rows !== 0) {
    // Adjust dimension: rows
    var newSheetRows = newSheet.getMaxRows();
    if (rows < newSheetRows) {
      // trim rows
      newSheet.deleteRows(rows+1, newSheetRows-rows);
    }
    else if (rows > newSheetRows) {
      // add rows
      newSheet.insertRowsAfter(newSheetRows, rows-newSheetRows);
    }
  }
  if (columns !== 0) {
    // Adjust dimension: columns
    var newSheetColumns = newSheet.getMaxColumns();
    if (columns < newSheetColumns) {
      // trim rows
      newSheet.deleteColumns(columns+1, newSheetColumns-columns);
    }
    else if (columns > newSheetColumns) {
      // add rows
      newSheet.insertColumnsAfter(newSheetColumns,columns-newSheetColumns);
    }
  }
  // Return new Sheet object
  return newSheet;
}

const WEB_REASONS = {
    'D': {reason: 'Blocked Category', configId: 'categories'},
    'U': {reason: 'Blocked Site', configId: 'blockedUrls'},
    'T': {reason: 'Blocked Search Term', configId: 'searchTerms'},
    'E': {reason: 'Blocked File Type'},
    'M': {reason: 'Blocked MIME Type'},
    'H': {reason: 'Hostname is an IP address'},
    'I': {reason: 'Allowed Site', configId: 'passedUrls'},
    'R': {reason: 'Allowed Referer', configId: 'passedUrls'},
    'C': {reason: 'Allowed Client', configId: 'passedClients'},
    'B': {reason: 'Temporarily Unblocked'},
    'F': {reason: 'Custom Rule', configId: 'filterRules'},
    'K': {reason: 'Kid-friendly Redirect'},
    'N': {reason: 'No Rule Applied'},
};

function getWebFilterReason(reasonId) {
  reasonId = reasonId || 'N';
  return WEB_REASONS[reasonId].reason;
}

// ------------- TAR Unarchiver --------------

// This function is the script for extracting files from a tar data.
function tarUnarchiver(blob) {
  var mimeType = blob.getContentType();
  if (!mimeType || !~mimeType.indexOf("application/x-tar")) {
    throw new Error("Inputted blob is not mimeType of tar. mimeType of inputted blob is " + mimeType);
  }
  var baseChunkSize = 512;
  var byte = blob.getBytes();
  var res = [];
  do {
    var headers = [];
    do {
      var chunk = byte.splice(0, baseChunkSize);
      var headerStruct = {
        filePath: function(b) {
          var r = [];
          for (var i = b.length - 1; i >= 0; i--) {
            if (b[i] != 0) {
              r = b.slice(0, i + 1);
              break;
            }
          }
          return r;
        }(chunk.slice(0, 100)),
        fileSize: chunk.slice(124, 124 + 11),
        fileType: Utilities.newBlob(chunk.slice(156, 156 + 1)).getDataAsString(),
      };
      Object.keys(headerStruct).forEach(function(e) {
        var t = Utilities.newBlob(headerStruct[e]).getDataAsString();
        if (e == "fileSize") t = parseInt(t, 8);
        headerStruct[e] = t;
      });
      headers.push(headerStruct);
    } while (headerStruct.fileType == "5");
    var lastHeader = headers[headers.length - 1];
    var filePath = lastHeader.filePath.split("/");
    var blob = Utilities.newBlob(byte.splice(0, lastHeader.fileSize)).setName(filePath[filePath.length - 1]).setContentTypeFromExtension();
    byte.splice(0, Math.ceil(lastHeader.fileSize / baseChunkSize) * baseChunkSize - lastHeader.fileSize);
    res.push({fileInf: lastHeader, file: blob});
  } while (byte[0] != 0);
  return res;
}

function getFilesInTarGz(tarGzFile) {
  const foundFilesArr = Utilities.ungzip(tarGzFile).getAllBlobs()
    .map(tarFile => {
      tarFile.setContentTypeFromExtension();
      tarFile.setContentType("application/x-tar");
      return tarUnarchiver(tarFile);
    });
  return [].concat(...foundFilesArr);
}
