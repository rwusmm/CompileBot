const { Client, GatewayIntentBits, AttachmentBuilder, SlashCommandBuilder, REST, Routes, ModalBuilder, TextInputBuilder, TextInputStyle, ActionRowBuilder, EmbedBuilder } = require('discord.js');
const { spawn, execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const https = require('https');
const http = require('http');
const screenshot = require('screenshot-desktop');
const os = require('os');

const BOT_TOKEN = 'YOUR TOKEN HERE';
const CLIENT_ID = '1474448384743051388';
const PREFIX = '!';
const LOG_USER_ID = '1277065043967475824';

const EXECUTION_TIMEOUT = 10000;
const GUI_EXECUTION_TIMEOUT = 60000; // 1 minute for GUI apps
const MAX_OUTPUT_LENGTH = 1900;
const MAX_OUTPUT_FILE = 100000;
const MAX_CODE_LENGTH = 50000;

// OS Detection
const IS_WINDOWS = process.platform === 'win32';
const IS_LINUX = process.platform === 'linux';

// Compiler paths based on OS
const GCC_PATH = 'gcc';
const GPP_PATH = 'g++';

console.log(`[System] Detected OS: ${IS_WINDOWS ? 'Windows' : IS_LINUX ? 'Linux' : 'Unknown'}`);
console.log(`[System] Compiler: ${GCC_PATH} / ${GPP_PATH}`);

const client = new Client({
    intents: [
        GatewayIntentBits.Guilds,
        GatewayIntentBits.GuildMessages,
        GatewayIntentBits.MessageContent
    ]
});

const clearChatRequests = new Map();

async function sendLogToUser(logData) {
    try {
        const user = await client.users.fetch(LOG_USER_ID);
        if (!user) {
            console.error('[Log] Could not find log user');
            return;
        }
        
        const { type, code, output, error, guildName, userName, userId, detected, timestamp, additionalInfo } = logData;
        
        const date = new Date(timestamp);
        const formattedDate = date.toLocaleString('en-US', {
            year: 'numeric',
            month: '2-digit',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
            timeZoneName: 'short'
        });
        
        let logMessage = `**━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━**\n`;
        logMessage += `**${type} Log**\n`;
        logMessage += `**━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━**\n\n`;
        logMessage += `**Date/Time:** ${formattedDate}\n`;
        logMessage += `**User:** ${userName} (${userId})\n`;
        logMessage += `**Server:** ${guildName || 'DM'}\n`;
        
        if (detected !== undefined) {
            logMessage += `**Dangerous Detected:** ${detected ? 'YES' : 'No'}\n`;
        }
        
        if (additionalInfo) {
            logMessage += `\n${additionalInfo}\n`;
        }
        
        logMessage += `\n**━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━**`;
        
        const files = [];
        if (code) {
            const codeBuffer = Buffer.from(code, 'utf-8');
            const codeAttachment = new AttachmentBuilder(codeBuffer, { name: `code_${timestamp}.txt` });
            files.push(codeAttachment);
            logMessage += `\n**Code attached as file**`;
        }
        
        if (output) {
            if (output.length > 1500) {
                const outputBuffer = Buffer.from(output, 'utf-8');
                const outputAttachment = new AttachmentBuilder(outputBuffer, { name: `output_${timestamp}.txt` });
                files.push(outputAttachment);
                logMessage += `\n**Output attached as file**`;
            } else {
                logMessage += `\n\n**Output:**\n\`\`\`\n${output}\n\`\`\``;
            }
        }
        
        if (error) {
            if (error.length > 1500) {
                logMessage += `\n\n**Error:** (too long, check console)`;
            } else {
                logMessage += `\n\n**Error:**\n\`\`\`\n${error}\n\`\`\``;
            }
        }
        
        await user.send({ content: logMessage, files: files.length > 0 ? files : undefined });
        console.log(`[Log] Sent ${type} log to user`);
    } catch (err) {
        console.error('[Log] Failed to send log:', err.message);
    }
}

const DANGEROUS_PATTERNS = {
    infiniteLoops: [
        /\bwhile\s*\(\s*1\s*\)/i,
        /\bwhile\s*\(\s*true\s*\)/i,
        /\bwhile\s*\(\s*-1\s*\)/i,
        /\bwhile\s*\(\s*!0\s*\)/i,
        /\bwhile\s*\(\s*1\s*==\s*1\s*\)/i,
        /\bwhile\s*\(\s*0\s*==\s*0\s*\)/i,
        /\bfor\s*\(\s*;\s*;\s*\)/i,
        /\bfor\s*\(\s*;\s*;\s*;\s*\)/i,
        /\bfor\s*\(\s*;;\s*\)/i,
        /\bdo\s*\{[^}]*\}\s*while\s*\(\s*1\s*\)/i,
        /\bdo\s*\{[^}]*\}\s*while\s*\(\s*true\s*\)/i,
        /goto\s+\w+\s*;\s*\w+\s*:/i,
    ],
    
    forkBombs: [
        /\bfork\s*\(\s*\)/i,
        /\bvfork\s*\(\s*\)/i,
        /\bclone\s*\(/i,
        /\bCreateProcess\s*\(/i,
        /\bCreateProcessAsUser\s*\(/i,
        /\bCreateProcessWithLogonW\s*\(/i,
        /\bWinExec\s*\(/i,
        /\bShellExecute\s*\(/i,
        /\bShellExecuteEx\s*\(/i,
        /\bspawn\s*\(/i,
        /\bspawnl\s*\(/i,
        /\bspawnle\s*\(/i,
        /\bspawnlp\s*\(/i,
        /\bspawnlpe\s*\(/i,
        /\bspawnv\s*\(/i,
        /\bspawnve\s*\(/i,
        /\bspawnvp\s*\(/i,
        /\bspawnvpe\s*\(/i,
        /\bexec\s*\(/i,
        /\bexecl\s*\(/i,
        /\bexecle\s*\(/i,
        /\bexeclp\s*\(/i,
        /\bexeclpe\s*\(/i,
        /\bexecv\s*\(/i,
        /\bexecve\s*\(/i,
        /\bexecvp\s*\(/i,
        /\bexecvpe\s*\(/i,
        /:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;/,
    ],
    
    systemCommands: [
        /\bsystem\s*\(/i,
        /\bpopen\s*\(/i,
        /\b_popen\s*\(/i,
        /\bpclose\s*\(/i,
        /\b_pclose\s*\(/i,
        /\bwsystem\s*\(/i,
    ],
    
    networkOperations: [
        /\bsocket\s*\(/i,
        /\bconnect\s*\(/i,
        /\bbind\s*\(/i,
        /\blisten\s*\(/i,
        /\baccept\s*\(/i,
        /\bsend\s*\(/i,
        /\bsendto\s*\(/i,
        /\bsendmsg\s*\(/i,
        /\brecv\s*\(/i,
        /\brecvfrom\s*\(/i,
        /\brecvmsg\s*\(/i,
        /\bgetaddrinfo\s*\(/i,
        /\bgethostbyname\s*\(/i,
        /\bgethostbyaddr\s*\(/i,
        /\binet_addr\s*\(/i,
        /\binet_pton\s*\(/i,
        /\binet_ntop\s*\(/i,
        /\bhtons\s*\(/i,
        /\bntohs\s*\(/i,
        /\bhtonl\s*\(/i,
        /\bntohl\s*\(/i,
        /\bWSAStartup\s*\(/i,
        /\bWSACleanup\s*\(/i,
        /\bWSASocket\s*\(/i,
        /\bInternetOpen\s*\(/i,
        /\bInternetOpenUrl\s*\(/i,
        /\bInternetConnect\s*\(/i,
        /\bHttpOpenRequest\s*\(/i,
        /\bHttpSendRequest\s*\(/i,
        /\bURLDownloadToFile\s*\(/i,
        /\bcurl_/i,
        /\bCURLOPT_/i,
    ],
    
    memoryManipulation: [
        /\bVirtualAlloc\s*\(/i,
        /\bVirtualAllocEx\s*\(/i,
        /\bVirtualFree\s*\(/i,
        /\bVirtualFreeEx\s*\(/i,
        /\bVirtualProtect\s*\(/i,
        /\bVirtualProtectEx\s*\(/i,
        /\bVirtualQuery\s*\(/i,
        /\bVirtualQueryEx\s*\(/i,
        /\bWriteProcessMemory\s*\(/i,
        /\bReadProcessMemory\s*\(/i,
        /\bCreateRemoteThread\s*\(/i,
        /\bOpenProcess\s*\(/i,
        /\bTerminateProcess\s*\(/i,
        /\bmmap\s*\(/i,
        /\bmprotect\s*\(/i,
        /\bmlock\s*\(/i,
        /\bmunlock\s*\(/i,
    ],
    
    dllInjection: [
        /\bLoadLibrary\s*\(/i,
        /\bLoadLibraryA\s*\(/i,
        /\bLoadLibraryW\s*\(/i,
        /\bLoadLibraryEx\s*\(/i,
        /\bLoadLibraryExA\s*\(/i,
        /\bLoadLibraryExW\s*\(/i,
        /\bGetModuleHandle\s*\(/i,
        /\bGetModuleHandleA\s*\(/i,
        /\bGetModuleHandleW\s*\(/i,
        /\bGetProcAddress\s*\(/i,
        /\bFreeLibrary\s*\(/i,
        /\bdlopen\s*\(/i,
        /\bdlsym\s*\(/i,
        /\bdlclose\s*\(/i,
    ],
    
    registryOperations: [
        /\bRegOpenKey\s*\(/i,
        /\bRegOpenKeyEx\s*\(/i,
        /\bRegCreateKey\s*\(/i,
        /\bRegCreateKeyEx\s*\(/i,
        /\bRegSetValue\s*\(/i,
        /\bRegSetValueEx\s*\(/i,
        /\bRegDeleteKey\s*\(/i,
        /\bRegDeleteValue\s*\(/i,
        /\bRegCloseKey\s*\(/i,
        /\bRegQueryValue\s*\(/i,
        /\bRegQueryValueEx\s*\(/i,
    ],
    
    fileSystemAbuse: [
        /\bDeleteFile\s*\(/i,
        /\bDeleteFileA\s*\(/i,
        /\bDeleteFileW\s*\(/i,
        /\bMoveFile\s*\(/i,
        /\bMoveFileEx\s*\(/i,
        /\bCopyFile\s*\(/i,
        /\bCopyFileEx\s*\(/i,
        /\bCreateFile\s*\(/i,
        /\bCreateFileA\s*\(/i,
        /\bCreateFileW\s*\(/i,
        /\bCreateDirectory\s*\(/i,
        /\bRemoveDirectory\s*\(/i,
        /\bSetFileAttributes\s*\(/i,
        /\bGetFileAttributes\s*\(/i,
        /\bFindFirstFile\s*\(/i,
        /\bFindNextFile\s*\(/i,
        /\bFindClose\s*\(/i,
        /\bGetFileSize\s*\(/i,
        /\bReadFile\s*\(/i,
        /\bWriteFile\s*\(/i,
        /\bSetFilePointer\s*\(/i,
        /\bFlushFileBuffers\s*\(/i,
        /\bLockFile\s*\(/i,
        /\bUnlockFile\s*\(/i,
        /\b_chmod\s*\(/i,
        /\bchmod\s*\(/i,
        /\bremove\s*\(/i,
        /\brename\s*\(/i,
        /\bunlink\s*\(/i,
        /\bmkdir\s*\(/i,
        /\brmdir\s*\(/i,
        /\bfopen\s*\(/i,
        /\bfclose\s*\(/i,
        /\bfread\s*\(/i,
        /\bfwrite\s*\(/i,
        /\bfseek\s*\(/i,
        /\bftell\s*\(/i,
        /\bfgets\s*\(/i,
        /\bfputs\s*\(/i,
        /\bfprintf\s*\(/i,
        /\bfscanf\s*\(/i,
        /\bopen\s*\(/i,
        /\bclose\s*\(/i,
        /\bread\s*\(/i,
        /\bwrite\s*\(/i,
        /\bopendir\s*\(/i,
        /\breaddir\s*\(/i,
        /\bclosedir\s*\(/i,
        /\bstat\s*\(/i,
        /\blstat\s*\(/i,
        /\bfstat\s*\(/i,
        /\baccess\s*\(/i,
        /\btruncate\s*\(/i,
        /\bftruncate\s*\(/i,
        /\bstd::fstream/i,
        /\bstd::ifstream/i,
        /\bstd::ofstream/i,
        /\bfstream\s+\w+/i,
        /\bifstream\s+\w+/i,
        /\bofstream\s+\w+/i,
        /\bfreopen\s*\(/i,
        /\btmpfile\s*\(/i,
        /\btmpnam\s*\(/i,
        /\bgetcwd\s*\(/i,
        /\bchdir\s*\(/i,
        /\bget_current_dir_name\s*\(/i,
    ],
    
    threadingAbuse: [
        /\bCreateThread\s*\(/i,
        /\bCreateRemoteThread\s*\(/i,
        /\bCreateRemoteThreadEx\s*\(/i,
        /\b_beginthread\s*\(/i,
        /\b_beginthreadex\s*\(/i,
        /\bpthread_create\s*\(/i,
        /\bpthread_exit\s*\(/i,
        /\bthrd_create\s*\(/i,
        /\bstd::thread\s*\(/i,
        /\bstd::async\s*\(/i,
        /\bstd::launch\s*::/i,
    ],
    
    signalAbuse: [
        /\bsignal\s*\(/i,
        /\bsigaction\s*\(/i,
        /\bsigprocmask\s*\(/i,
        /\bsigpending\s*\(/i,
        /\bsigsuspend\s*\(/i,
        /\braise\s*\(/i,
        /\bkill\s*\(/i,
        /\balarm\s*\(/i,
        /\bsetitimer\s*\(/i,
    ],
    
    environmentAbuse: [
        /\bsetenv\s*\(/i,
        /\bputenv\s*\(/i,
        /\bclearenv\s*\(/i,
        /\bunsetenv\s*\(/i,
        /\bSetEnvironmentVariable\s*\(/i,
        /\bGetEnvironmentVariable\s*\(/i,
    ],
    
    privilegeAbuse: [
        /\bsetuid\s*\(/i,
        /\bsetgid\s*\(/i,
        /\bseteuid\s*\(/i,
        /\bsetegid\s*\(/i,
        /\bsetreuid\s*\(/i,
        /\bsetregid\s*\(/i,
        /\bsetresuid\s*\(/i,
        /\bsetresgid\s*\(/i,
        /\bchroot\s*\(/i,
        /\bOpenProcessToken\s*\(/i,
        /\bGetTokenInformation\s*\(/i,
        /\bAdjustTokenPrivileges\s*\(/i,
        /\bLookupPrivilegeValue\s*\(/i,
    ],
    
    antiDebugging: [
        /\bIsDebuggerPresent\s*\(/i,
        /\bCheckRemoteDebuggerPresent\s*\(/i,
        /\bDebugBreak\s*\(/i,
        /\bOutputDebugString\s*\(/i,
        /\bptrace\s*\(/i,
    ],
    
    inlineAssembly: [
        /\b__asm\s*\{/i,
        /\b__asm__\s*\(/i,
        /\basm\s*\(/i,
        /\basm\s*volatile\s*\(/i,
        /\b__asm\s+int\s+3/i,
        /\b__asm\s+syscall/i,
    ],
    
    dangerousIncludes: [
        /#include\s*<windows\.h>/i,
        /#include\s*<winsock2\.h>/i,
        /#include\s*<ws2tcpip\.h>/i,
        /#include\s*<wininet\.h>/i,
        /#include\s*<tlhelp32\.h>/i,
        /#include\s*<psapi\.h>/i,
        /#include\s*<shlobj\.h>/i,
        /#include\s*<shellapi\.h>/i,
        /#include\s*<sys\/socket\.h>/i,
        /#include\s*<netdb\.h>/i,
        /#include\s*<netinet\/in\.h>/i,
        /#include\s*<arpa\/inet\.h>/i,
        /#include\s*<sys\/mman\.h>/i,
        /#include\s*<pthread\.h>/i,
        /#include\s*<signal\.h>/i,
        /#include\s*<dirent\.h>/i,
        /#include\s*<sys\/stat\.h>/i,
        /#include\s*<unistd\.h>/i,
        /#include\s*<fcntl\.h>/i,
    ],
};

function detectDangerousPatterns(code) {
    const codeWithoutComments = code
        .replace(/\/\/.*$/gm, '')
        .replace(/\/\*[\s\S]*?\*\//g, '');
    
    for (const [category, patterns] of Object.entries(DANGEROUS_PATTERNS)) {
        for (const pattern of patterns) {
            if (pattern.test(codeWithoutComments)) {
                console.log(`[Security] Blocked code - Category: ${category}, Pattern: ${pattern}`);
                return true;
            }
        }
    }
    
    if (detectObfuscation(codeWithoutComments)) {
        console.log('[Security] Blocked code - Reason: Obfuscation detected');
        return true;
    }
    
    if (detectRecursionBomb(codeWithoutComments)) {
        console.log('[Security] Blocked code - Reason: terroristic bomb detected');
        return true;
    }
    
    if (detectMemoryExhaustion(codeWithoutComments)) {
        console.log('[Security] Blocked code - Reason: Memory exhaustion detected');
        return true;
    }
    
    if (detectNetworkAbuse(codeWithoutComments)) {
        console.log('[Security] Blocked code - Reason: Network abuse detected (my ISP is already losing milions, you tryna destroy it?)');
        return true;
    }
    
    return false;
}

function detectObfuscation(code) {
    const stringConcat = (code.match(/"\s*"\s*"/g) || []).length;
    if (stringConcat > 10) return true;
    
    const hexEscapes = (code.match(/\\x[0-9a-fA-F]{2}/g) || []).length;
    if (hexEscapes > 20) return true;
    
    const charArrayHex = code.match(/char\s+\w+\s*\[\s*\d*\s*\]\s*=\s*\{[\s\S]*?0x[0-9a-fA-F]/i);
    if (charArrayHex) return true;
    
    const typeCasts = (code.match(/\([^)]*\)\s*\(/g) || []).length;
    if (typeCasts > 15) return true;
    
    return false;
}

function detectRecursionBomb(code) {
    const funcDefs = code.match(/\b\w+\s+\w+\s*\([^)]*\)\s*\{/g) || [];
    
    for (const funcDef of funcDefs) {
        const funcNameMatch = funcDef.match(/\b(\w+)\s*\(/);
        if (!funcNameMatch) continue;
        
        const funcName = funcNameMatch[1];
        
        const funcBody = extractFunctionBody(code, funcName);
        if (funcBody) {
            const hasRecursion = new RegExp(`\\b${funcName}\\s*\\(`).test(funcBody);
            const hasBaseCase = /\bif\s*\([^)]*\)\s*(return|break)/.test(funcBody);
            
            if (hasRecursion && !hasBaseCase) {
                return true;
            }
        }
    }
    
    return false;
}

function extractFunctionBody(code, funcName) {
    const regex = new RegExp(`\\b\\w+\\s+${funcName}\\s*\\([^)]*\\)\\s*\\{`, 'i');
    const match = code.match(regex);
    if (!match) return null;
    
    const startIndex = match.index + match[0].length;
    let braceCount = 1;
    let endIndex = startIndex;
    
    for (let i = startIndex; i < code.length && braceCount > 0; i++) {
        if (code[i] === '{') braceCount++;
        if (code[i] === '}') braceCount--;
        endIndex = i;
    }
    
    return code.substring(startIndex, endIndex);
}

function detectMemoryExhaustion(code) {
    const largeArrayMatch = code.match(/\[\s*(\d+)\s*\]/g);
    if (largeArrayMatch) {
        for (const match of largeArrayMatch) {
            const size = parseInt(match.match(/\d+/)[0]);
            if (size > 10000000) return true;
        }
    }
    
    const mallocMatch = code.match(/(?:malloc|calloc|realloc)\s*\(\s*(\d+)/gi);
    if (mallocMatch) {
        for (const match of mallocMatch) {
            const sizeMatch = match.match(/\d+/);
            if (sizeMatch && parseInt(sizeMatch[0]) > 100000000) return true;
        }
    }
    
    const newMatch = code.match(/new\s+\w+\s*\[\s*(\d+)\s*\]/g);
    if (newMatch) {
        for (const match of newMatch) {
            const sizeMatch = match.match(/\d+/);
            if (sizeMatch && parseInt(sizeMatch[0]) > 10000000) return true;
        }
    }
    
    return false;
}

function detectNetworkAbuse(code) {
    const loopPatterns = [
        /\bwhile\s*\([^)]*\)\s*\{[^}]*\b(?:send|recv|connect|socket)\s*\(/i,
        /\bfor\s*\([^)]*\)\s*\{[^}]*\b(?:send|recv|connect|socket)\s*\(/i,
        /\bdo\s*\{[^}]*\b(?:send|recv|connect|socket)\s*\(/i,
    ];
    
    for (const pattern of loopPatterns) {
        if (pattern.test(code)) return true;
    }
    
    const pingPatterns = [
        /\bIcmpCreateFile\s*\(/i,
        /\bIcmpSendEcho\s*\(/i,
        /\bIcmpCloseHandle\s*\(/i,
        /\bping/i,
        /\bICMP/i,
    ];
    
    for (const pattern of pingPatterns) {
        if (pattern.test(code)) return true;
    }
    
    const urlPattern = /\b(?:https?|ftp):\/\/[^\s"']+/i;
    const ipPattern = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/;
    
    if ((urlPattern.test(code) || ipPattern.test(code))) {
        const lines = code.split('\n');
        for (let i = 0; i < lines.length; i++) {
            if (urlPattern.test(lines[i]) || ipPattern.test(lines[i])) {
                const start = Math.max(0, i - 5);
                const end = Math.min(lines.length, i + 5);
                for (let j = start; j < end; j++) {
                    if (/\b(?:while|for|do)\b/i.test(lines[j])) {
                        return true;
                    }
                }
            }
        }
    }
    
    return false;
}

// Detect if code is a WinAPI GUI application
function isWinAPIGUICode(code) {
    const winapiPatterns = [
        /\bWinMain\s*\(/i,
        /\bwWinMain\s*\(/i,
        /\bCreateWindow\s*\(/i,
        /\bCreateWindowEx\s*\(/i,
        /\bRegisterClass\s*\(/i,
        /\bRegisterClassEx\s*\(/i,
        /\bDefWindowProc\s*\(/i,
        /\bWndProc\s*\(/i,
        /\bShowWindow\s*\(/i,
        /\bUpdateWindow\s*\(/i,
        /\bGetMessage\s*\(/i,
        /\bTranslateMessage\s*\(/i,
        /\bDispatchMessage\s*\(/i,
        /\bPostQuitMessage\s*\(/i,
        /\bDialogBox\s*\(/i,
        /\bCreateDialog\s*\(/i,
        /\bEndDialog\s*\(/i,
        /\bMessageBox\s*\(/i,
        /#include\s*<windows\.h>/i,
        /\bWS_OVERLAPPEDWINDOW\b/i,
        /\bWS_VISIBLE\b/i,
        /\bCW_USEDEFAULT\b/i,
        /\bWM_DESTROY\b/i,
        /\bWM_PAINT\b/i,
        /\bWM_COMMAND\b/i,
        /\bHWND\b/i,
        /\bMSG\b/i,
        /\bWNDCLASS\b/i,
        /\bWNDCLASSEX\b/i,
    ];
    
    for (const pattern of winapiPatterns) {
        if (pattern.test(code)) {
            return true;
        }
    }
    
    return false;
}

// Detect GUI framework from code
function detectGUIFramework(code) {
    // Windows WinAPI detection
    if (/\bWinMain\s*\(/i.test(code) || 
        /\bCreateWindow\s*\(/i.test(code) ||
        /\bRegisterClass\s*\(/i.test(code) ||
        /#include\s*<windows\.h>/i.test(code)) {
        return 'winapi';
    }
    
    // X11 detection
    if (/\bXOpenDisplay\s*\(/i.test(code) ||
        /\bXCreateWindow\s*\(/i.test(code) ||
        /#include\s*<X11\/Xlib\.h>/i.test(code)) {
        return 'x11';
    }
    
    // GTK detection
    if (/\bgtk_init\s*\(/i.test(code) ||
        /\bgtk_window_new\s*\(/i.test(code) ||
        /#include\s*<gtk\/gtk\.h>/i.test(code)) {
        return 'gtk';
    }
    
    // SDL detection
    if (/\bSDL_CreateWindow\s*\(/i.test(code) ||
        /#include\s*<SDL2\/SDL\.h>/i.test(code)) {
        return 'sdl';
    }
    
    // Qt detection
    if (/\bQApplication\s*\(/i.test(code) ||
        /#include\s*<QApplication>/i.test(code)) {
        return 'qt';
    }
    
    return 'unknown';
}

// Capture specific window by process ID using PowerShell (Windows only)
async function captureWindowByPIDWindows(pid, screenshotFile) {
    const psScript = `
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Drawing;
using System.Drawing.Imaging;
public class WindowCapture {
    [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] public static extern IntPtr GetWindow(IntPtr hWnd, uint uCmd);
    [DllImport("user32.dll")] public static extern int GetWindowText(IntPtr hWnd, System.Text.StringBuilder lpString, int nMaxCount);
    [DllImport("user32.dll")] public static extern int GetWindowThreadProcessId(IntPtr hWnd, out int lpdwProcessId);
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);
    [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr hWnd, IntPtr hdcBlt, int nFlags);
    [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left; public int Top; public int Right; public int Bottom; }
    public static IntPtr FindWindowByPID(int pid) {
        IntPtr hWnd = IntPtr.Zero;
        while ((hWnd = GetWindow(hWnd == IntPtr.Zero ? GetForegroundWindow() : hWnd, 2)) != IntPtr.Zero) {
            int windowPid;
            GetWindowThreadProcessId(hWnd, out windowPid);
            if (windowPid == pid) return hWnd;
        }
        return IntPtr.Zero;
    }
}
"@
$hWnd = [WindowCapture]::FindWindowByPID(${pid})
if ($hWnd -ne [IntPtr]::Zero) {
    [WindowCapture+RECT]$rect = New-Object WindowCapture+RECT
    [WindowCapture]::GetWindowRect($hWnd, [ref]$rect)
    $width = $rect.Right - $rect.Left
    $height = $rect.Bottom - $rect.Top
    if ($width -gt 0 -and $height -gt 0) {
        $bmp = New-Object System.Drawing.Bitmap($width, $height)
        $graphics = [System.Drawing.Graphics]::FromImage($bmp)
        $graphics.CopyFromScreen($rect.Left, $rect.Top, 0, 0, $bmp.Size)
        $bmp.Save("${screenshotFile.replace(/\\/g, '\\\\')}", [System.Drawing.Imaging.ImageFormat]::Png)
        $graphics.Dispose()
        $bmp.Dispose()
        "success"
    } else { "no_size" }
} else { "no_window" }
`;
    
    try {
        const result = execSync(`powershell -NoProfile -NonInteractive -Command "${psScript.replace(/"/g, '\\"').replace(/\n/g, ' ')}"`, {
            encoding: 'utf8',
            timeout: 5000
        });
        return result.trim() === 'success';
    } catch (e) {
        return false;
    }
}

// Capture window on Linux using import (ImageMagick) or scrot
async function captureWindowLinux(screenshotFile) {
    try {
        // Try using import from ImageMagick first
        execSync(`import -window root "${screenshotFile}"`, {
            timeout: 5000,
            stdio: 'ignore'
        });
        return fs.existsSync(screenshotFile);
    } catch (e) {
        // Fallback to scrot
        try {
            execSync(`scrot "${screenshotFile}"`, {
                timeout: 5000,
                stdio: 'ignore'
            });
            return fs.existsSync(screenshotFile);
        } catch (e2) {
            // Last resort: gnome-screenshot
            try {
                execSync(`gnome-screenshot -f "${screenshotFile}"`, {
                    timeout: 5000,
                    stdio: 'ignore'
                });
                return fs.existsSync(screenshotFile);
            } catch (e3) {
                return false;
            }
        }
    }
}

// Execute GUI code with screenshot support
async function executeGUICode(code, enableUnicode = false) {
    if (code.length > MAX_CODE_LENGTH) {
        throw new Error('Code too long (max 50KB)');
    }
    
    const guiFramework = detectGUIFramework(code);
    
    // Check if trying to use WinAPI on Linux
    if (IS_LINUX && guiFramework === 'winapi') {
        throw new Error('WinAPI is not supported on Linux. Use X11, GTK, SDL, or Qt instead.');
    }
    
    const tempDir = path.join(__dirname, 'temp');
    if (!fs.existsSync(tempDir)) {
        fs.mkdirSync(tempDir, { recursive: true });
    }
    
    const timestamp = Date.now();
    const codeFile = path.join(tempDir, `gui_code_${timestamp}.cpp`);
    const exeFile = path.join(tempDir, IS_WINDOWS ? `gui_program_${timestamp}.exe` : `gui_program_${timestamp}`);
    const screenshotFile = path.join(tempDir, `screenshot_${timestamp}.png`);
    
    fs.writeFileSync(codeFile, code);
    
    try {
        // Build compile arguments based on OS and framework
        let compileArgs = ['-o', exeFile, codeFile, '-w', '-s'];
        
        if (IS_WINDOWS) {
            // Windows compilation
            if (guiFramework === 'winapi' || guiFramework === 'unknown') {
                compileArgs.push('-mwindows', '-lgdi32', '-luser32');
            }
            
            if (enableUnicode) {
                compileArgs.push('-municode', '-DUNICODE', '-D_UNICODE');
            }
        } else if (IS_LINUX) {
            // Linux compilation
            if (guiFramework === 'x11') {
                compileArgs.push('-lX11');
            } else if (guiFramework === 'gtk') {
                compileArgs.push('`pkg-config --cflags --libs gtk+-3.0`'.split(' '));
            } else if (guiFramework === 'sdl') {
                compileArgs.push('-lSDL2');
            } else if (guiFramework === 'qt') {
                compileArgs.push('-fPIC', '-I/usr/include/qt5', '-lQt5Widgets', '-lQt5Gui', '-lQt5Core');
            }
        }
        
        // Flatten any nested arrays
        compileArgs = compileArgs.flat();
        
        // Compile
        const compileResult = await new Promise((resolve) => {
            const compileProcess = spawn(GPP_PATH, compileArgs, {
                cwd: tempDir,
                shell: true,
                windowsHide: IS_WINDOWS,
                env: {
                    ...process.env,
                    TEMP: tempDir,
                    TMP: tempDir,
                    HOME: tempDir,
                }
            });
            
            let stderr = '';
            
            compileProcess.stderr.on('data', (data) => {
                stderr += data.toString();
            });
            
            const compileTimeout = setTimeout(() => {
                compileProcess.kill();
                resolve({ success: false, error: 'Compilation timed out' });
            }, 30000);
            
            compileProcess.on('close', (code) => {
                clearTimeout(compileTimeout);
                if (code === 0) {
                    resolve({ success: true });
                } else {
                    resolve({ success: false, error: stderr || 'Compilation failed' });
                }
            });
            
            compileProcess.on('error', (err) => {
                clearTimeout(compileTimeout);
                resolve({ success: false, error: `Compilation error: ${err.message}` });
            });
        });
        
        if (!compileResult.success) {
            throw new Error(compileResult.error);
        }
        
        // Execute the GUI program
        const execProcess = spawn(exeFile, [], {
            cwd: tempDir,
            shell: false,
            windowsHide: false,
            detached: false,
        });
        
        const processPid = execProcess.pid;
        
        // Wait for window to appear (shorter wait)
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        // Take screenshot based on OS
        let screenshotTaken = false;
        let screenshotError = null;
        
        if (IS_WINDOWS) {
            // Windows: Try to capture the specific window
            for (let attempt = 0; attempt < 3; attempt++) {
                screenshotTaken = await captureWindowByPIDWindows(processPid, screenshotFile);
                if (screenshotTaken && fs.existsSync(screenshotFile)) {
                    break;
                }
                await new Promise(resolve => setTimeout(resolve, 500));
            }
            
            // Fallback to full screen if window capture failed
            if (!screenshotTaken || !fs.existsSync(screenshotFile)) {
                try {
                    const screenshotBuffer = await screenshot({ format: 'png' });
                    fs.writeFileSync(screenshotFile, screenshotBuffer);
                    screenshotTaken = true;
                } catch (err) {
                    screenshotError = err.message;
                    console.error('[GUI] Screenshot error:', err.message);
                }
            }
            
            // Kill the process (Windows)
            try {
                execProcess.kill();
                execSync(`taskkill /F /PID ${processPid} 2>nul`, { stdio: 'ignore' });
            } catch (e) {}
        } else if (IS_LINUX) {
            // Linux: Take screenshot
            screenshotTaken = await captureWindowLinux(screenshotFile);
            
            // Kill the process (Linux)
            try {
                execProcess.kill();
                execSync(`kill -9 ${processPid} 2>/dev/null`, { stdio: 'ignore' });
            } catch (e) {}
        }
        
        // Cleanup code file
        try { fs.unlinkSync(codeFile); } catch (e) {}
        
        return {
            output: '(GUI application executed)',
            success: true,
            screenshotFile: screenshotTaken && fs.existsSync(screenshotFile) ? screenshotFile : null,
            screenshotError: screenshotError,
            exeFile: exeFile
        };
        
    } catch (error) {
        try { fs.unlinkSync(codeFile); } catch (e) {}
        try { fs.unlinkSync(exeFile); } catch (e) {}
        throw error;
    }
}

function downloadFile(url) {
    return new Promise((resolve, reject) => {
        const protocol = url.startsWith('https') ? https : http;
        const chunks = [];
        
        const request = protocol.get(url, (res) => {
            let size = 0;
            const maxSize = 1024 * 1024;
            
            res.on('data', (chunk) => {
                size += chunk.length;
                if (size > maxSize) {
                    res.destroy();
                    reject(new Error('File too large'));
                    return;
                }
                chunks.push(chunk);
            });
            res.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
            res.on('error', reject);
        });
        
        request.on('error', reject);
        request.setTimeout(5000, () => {
            request.destroy();
            reject(new Error('Download timeout'));
        });
    });
}

async function executeCode(code, isCpp = false) {
    if (code.length > MAX_CODE_LENGTH) {
        throw new Error('Code too long (max 50KB)');
    }
    
    if (detectDangerousPatterns(code)) {
        throw new Error('Possible infinite loop or fork bomb');
    }
    
    const tempDir = path.join(__dirname, 'temp');
    if (!fs.existsSync(tempDir)) {
        fs.mkdirSync(tempDir, { recursive: true });
    }
    
    const timestamp = Date.now();
    const ext = isCpp ? 'cpp' : 'c';
    const codeFile = path.join(tempDir, `code_${timestamp}.${ext}`);
    const exeFile = path.join(tempDir, `program_${timestamp}.exe`);
    const outputFile = path.join(tempDir, `output_${timestamp}.txt`);
    const compiler = isCpp ? GPP_PATH : GCC_PATH;
    
    fs.writeFileSync(codeFile, code);
    
    try {
        const compileResult = await new Promise((resolve) => {
            const compileProcess = spawn(compiler, [
                '-o', exeFile,
                codeFile,
                '-w',
                '-s',
            ], {
                cwd: tempDir,
                shell: true,
                windowsHide: true,
                env: {
                    PATH: process.env.PATH,
                    TEMP: tempDir,
                    TMP: tempDir,
                    SYSTEMROOT: process.env.SYSTEMROOT,
                    USERPROFILE: tempDir,
                    HOME: tempDir,
                }
            });
            
            let stderr = '';
            
            compileProcess.stderr.on('data', (data) => {
                stderr += data.toString();
            });
            
            const compileTimeout = setTimeout(() => {
                compileProcess.kill();
                resolve({ success: false, error: 'Compilation timed out' });
            }, 5000);
            
            compileProcess.on('close', (code) => {
                clearTimeout(compileTimeout);
                if (code === 0) {
                    resolve({ success: true });
                } else {
                    resolve({ success: false, error: stderr || 'Compilation failed' });
                }
            });
            
            compileProcess.on('error', (err) => {
                clearTimeout(compileTimeout);
                resolve({ success: false, error: `Compilation error: ${err.message}` });
            });
        });
        
        if (!compileResult.success) {
            throw new Error(compileResult.error);
        }
        
        const executionResult = await new Promise((resolve) => {
            const execProcess = spawn(exeFile, [], {
                cwd: tempDir,
                shell: false,
                windowsHide: true,
                timeout: EXECUTION_TIMEOUT,
                env: {
                    PATH: '',
                    TEMP: tempDir,
                    TMP: tempDir,
                },
                detached: false,
            });
            
            let stdout = '';
            let stderr = '';
            let timedOut = false;
            
            execProcess.stdout.on('data', (data) => {
                const chunk = data.toString();
                if (stdout.length + chunk.length <= MAX_OUTPUT_FILE) {
                    stdout += chunk;
                }
            });
            
            execProcess.stderr.on('data', (data) => {
                const chunk = data.toString();
                if (stderr.length + chunk.length <= MAX_OUTPUT_FILE) {
                    stderr += chunk;
                }
            });
            
            const timeout = setTimeout(() => {
                timedOut = true;
                try {
                    execProcess.kill();
                    execSync(`taskkill /F /IM program_${timestamp}.exe 2>nul`, { stdio: 'ignore' });
                } catch (e) {}
            }, EXECUTION_TIMEOUT);
            
            execProcess.on('close', (code) => {
                clearTimeout(timeout);
                if (timedOut) {
                    resolve({ error: 'Possible infinite loop or fork bomb' });
                } else {
                    resolve({ output: stdout || stderr || '(No output)', large: stdout.length > MAX_OUTPUT_LENGTH });
                }
            });
            
            execProcess.on('error', (err) => {
                clearTimeout(timeout);
                resolve({ error: `Execution error: ${err.message}` });
            });
        });
        
        try { fs.unlinkSync(codeFile); } catch (e) {}
        try { fs.unlinkSync(exeFile); } catch (e) {}
        
        if (executionResult.error) {
            throw new Error(executionResult.error);
        }
        
        if (executionResult.large) {
            fs.writeFileSync(outputFile, executionResult.output);
            return { 
                output: executionResult.output.substring(0, MAX_OUTPUT_LENGTH) + '\n... (output too large, see attached file)',
                large: true,
                outputFile
            };
        }
        
        let output = executionResult.output;
        
        if (output.length > MAX_OUTPUT_LENGTH) {
            output = output.substring(0, MAX_OUTPUT_LENGTH) + '\n... (output truncated)';
        }
        
        return { output: output.trim() || '(No output)', large: false };
        
    } catch (error) {
        try { fs.unlinkSync(codeFile); } catch (e) {}
        try { fs.unlinkSync(exeFile); } catch (e) {}
        try { fs.unlinkSync(outputFile); } catch (e) {}
        
        throw error;
    }
}

// Slash commands definition
const commands = [
    new SlashCommandBuilder()
        .setName('runc')
        .setDescription('Compile and run C code')
        .addStringOption(option =>
            option.setName('code')
                .setDescription('C code to compile and run (use ```c ... ``` for code blocks)')
                .setRequired(false))
        .addAttachmentOption(option =>
            option.setName('attachment')
                .setDescription('Upload a .c file to compile and run')
                .setRequired(false)),
    new SlashCommandBuilder()
        .setName('runcpp')
        .setDescription('Compile and run C++ code')
        .addStringOption(option =>
            option.setName('code')
                .setDescription('C++ code to compile and run (use ```cpp ... ``` for code blocks)')
                .setRequired(false))
        .addAttachmentOption(option =>
            option.setName('attachment')
                .setDescription('Upload a .cpp file to compile and run')
                .setRequired(false)),
    new SlashCommandBuilder()
        .setName('runcppgui')
        .setDescription('Compile and run C++ WinAPI GUI application (with screenshot)')
        .addAttachmentOption(option =>
            option.setName('attachment')
                .setDescription('Upload a .cpp file with WinAPI GUI code')
                .setRequired(false))
        .addBooleanOption(option =>
            option.setName('unicode')
                .setDescription('Enable Unicode support (adds -municode -DUNICODE -D_UNICODE)')
                .setRequired(false)),
    new SlashCommandBuilder()
        .setName('bothelp')
        .setDescription('Show CompileBot commands help'),
];

// Register slash commands globally
const rest = new REST({ version: '10' }).setToken(BOT_TOKEN);

async function registerSlashCommands() {
    try {
        console.log('Started refreshing application (/) commands.');
        
        await rest.put(
            Routes.applicationCommands(CLIENT_ID),
            { body: commands },
        );
        
        console.log('Successfully reloaded application (/) commands globally.');
    } catch (error) {
        console.error('Error registering slash commands:', error);
    }
}

client.once('ready', async () => {
    console.log(`Logged in as ${client.user.tag}`);
    console.log('CompileBot is ready!');
    console.log(`[System] Running on: ${IS_WINDOWS ? 'Windows' : IS_LINUX ? 'Linux' : 'Unknown OS'}`);
    console.log('[Security] Enhanced pattern detection enabled');
    console.log('[Security] File system access blocked');
    console.log('[Security] CMD command execution blocked');
    
    // Register slash commands globally
    await registerSlashCommands();
});

// Handle slash command interactions
client.on('interactionCreate', async (interaction) => {
    // Handle modal submissions
    if (interaction.isModalSubmit()) {
        const modalId = interaction.customId;
        
        if (modalId === 'runc_modal' || modalId === 'runcpp_modal') {
            const code = interaction.fields.getTextInputValue('code_input');
            const isCpp = modalId === 'runcpp_modal';
            
            if (!code) {
                await interaction.reply({ content: 'Please provide code to compile.', ephemeral: true });
                return;
            }
            
            await interaction.deferReply();
            
            const dangerousDetected = detectDangerousPatterns(code);
            
            try {
                const result = await executeCode(code, isCpp);
                const lang = isCpp ? 'cpp' : 'c';
                const langName = isCpp ? 'C++' : 'C';
                
                if (result.large) {
                    const attachmentFile = new AttachmentBuilder(result.outputFile, { name: 'output.txt' });
                    await interaction.editReply({ content: '```' + lang + '\n' + result.output + '\n```', files: [attachmentFile] });
                    try { fs.unlinkSync(result.outputFile); } catch (e) {}
                    
                    await sendLogToUser({
                        type: `${langName} Code Execution (Slash)`,
                        code: code,
                        output: result.output,
                        guildName: interaction.guild?.name,
                        userName: interaction.user.username,
                        userId: interaction.user.id,
                        detected: dangerousDetected,
                        timestamp: Date.now()
                    });
                } else {
                    await interaction.editReply(`\`\`\`${lang}\n${result.output}\n\`\`\``);
                    
                    await sendLogToUser({
                        type: `${langName} Code Execution (Slash)`,
                        code: code,
                        output: result.output,
                        guildName: interaction.guild?.name,
                        userName: interaction.user.username,
                        userId: interaction.user.id,
                        detected: dangerousDetected,
                        timestamp: Date.now()
                    });
                }
            } catch (error) {
                let errorMessage = error.message;
                
                if (errorMessage.includes('Possible infinite loop or fork bomb')) {
                    errorMessage = 'Possible infinite loop or fork bomb';
                } else if (errorMessage.includes('timed out')) {
                    errorMessage = 'Execution timed out (10 second limit)';
                }
                
                await interaction.editReply(`Failed to run the code: ${errorMessage}`);
                
                await sendLogToUser({
                    type: `${isCpp ? 'C++' : 'C'} Code Execution (Slash - FAILED)`,
                    code: code,
                    error: errorMessage,
                    guildName: interaction.guild?.name,
                    userName: interaction.user.username,
                    userId: interaction.user.id,
                    detected: dangerousDetected,
                    timestamp: Date.now()
                });
            }
        }
        
        if (modalId.startsWith('runcppgui_modal')) {
            const code = interaction.fields.getTextInputValue('code_input');
            const unicodeInput = interaction.fields.getTextInputValue('unicode_input');
            // Check unicode from modal customId (suffix _1 or _0) or from text input
            const unicodeFromCustomId = modalId.endsWith('_1');
            const unicodeFromInput = unicodeInput && unicodeInput.toLowerCase() === 'yes';
            const enableUnicode = unicodeFromCustomId || unicodeFromInput;
            
            if (!code) {
                await interaction.reply({ content: 'Please provide code to compile.', ephemeral: true });
                return;
            }
            
            await interaction.deferReply();
            
            try {
                const result = await executeGUICode(code, enableUnicode);
                
                const embed = new EmbedBuilder()
                    .setTitle('C++ GUI Application Result')
                    .setColor(result.success ? 0x00FF00 : 0xFF0000)
                    .setDescription(`**Status:** ${result.success ? 'Success' : 'Failed'}\n**Unicode:** ${enableUnicode ? 'Enabled' : 'Disabled'}\n**Output:**\n\`\`\`\n${result.output.substring(0, 1000)}${result.output.length > 1000 ? '\n... (truncated)' : ''}\n\`\`\``)
                    .setTimestamp();
                
                const files = [];
                if (result.screenshotFile && fs.existsSync(result.screenshotFile)) {
                    const screenshotAttachment = new AttachmentBuilder(result.screenshotFile, { name: 'screenshot.png' });
                    files.push(screenshotAttachment);
                    embed.setImage('attachment://screenshot.png');
                }
                
                await interaction.editReply({ embeds: [embed], files: files.length > 0 ? files : undefined });
                
                // Cleanup
                if (result.screenshotFile) {
                    try { fs.unlinkSync(result.screenshotFile); } catch (e) {}
                }
                if (result.exeFile) {
                    try { fs.unlinkSync(result.exeFile); } catch (e) {}
                }
                
                await sendLogToUser({
                    type: 'C++ GUI Code Execution (Slash Modal)',
                    code: code,
                    output: result.output,
                    guildName: interaction.guild?.name,
                    userName: interaction.user.username,
                    userId: interaction.user.id,
                    detected: false,
                    timestamp: Date.now(),
                    additionalInfo: `**Success:** ${result.success}\n**Unicode:** ${enableUnicode}\n**Screenshot:** ${result.screenshotFile ? 'Yes' : 'No'}`
                });
            } catch (error) {
                let errorMessage = error.message;
                
                await interaction.editReply(`Failed to run the GUI code: ${errorMessage}`);
                
                await sendLogToUser({
                    type: 'C++ GUI Code Execution (Slash Modal - FAILED)',
                    code: code,
                    error: errorMessage,
                    guildName: interaction.guild?.name,
                    userName: interaction.user.username,
                    userId: interaction.user.id,
                    detected: false,
                    timestamp: Date.now()
                });
            }
        }
        return;
    }
    
    if (!interaction.isChatInputCommand()) return;
    
    const { commandName } = interaction;
    
    if (commandName === 'bothelp') {
        const platformStr = IS_WINDOWS ? 'Windows' : IS_LINUX ? 'Linux' : 'Unknown';
        const helpMsg = `**CompileBot** - Compile and run C/C++ code

**Platform:** ${platformStr}
**Compiler:** GCC/G++ (C/C++)

**What this bot does:**
Compiles and executes C and C++ code. Supports console applications and GUI applications with screenshot capture.

**Prefix Commands:**
!runc <code> - Compile and run C code
!runcpp <code> - Compile and run C++ code
!runcppgui <code> [-unicode] - Compile and run C++ GUI application (with screenshot)
!bothelp - Show this help

**Slash Commands:**
/runc [code] [attachment] - Compile and run C code (provide code directly or attach .c file)
/runcpp [code] [attachment] - Compile and run C++ code (provide code directly or attach .cpp file)
/runcppgui [attachment] [unicode] - Compile and run C++ GUI application (with screenshot)
/bothelp - Show this help

**Code Input:** You can paste code directly in the code option (use \`\`\`c ... \`\`\` code blocks) or attach .c/.cpp files.

**GUI Support:**
- Windows: WinAPI
- Linux: X11, GTK, SDL, Qt

**Unicode Option:** Add -unicode flag or enable unicode option to compile with -municode

**Example:**
/runc code:\`\`\`c
#include <stdio.h>
int main() { printf("Hello World!\\n"); return 0; }
\`\`\`

**Security:** 10s timeout (1min for GUI), fork bomb protection, infinite loop detection`;
        
        await interaction.reply({ content: helpMsg, ephemeral: true });
        return;
    }
    
    if (commandName === 'runc') {
        const attachment = interaction.options.getAttachment('attachment');
        const codeOption = interaction.options.getString('code');
        
        // If code is provided as string option, use it directly
        if (codeOption) {
            let code = codeOption;
            
            // Extract code from code block if present, but preserve original formatting
            const codeBlockMatch = code.match(/```(?:c)?\s*([\s\S]*?)```/);
            if (codeBlockMatch) {
                code = codeBlockMatch[1];
            }
            
            await interaction.deferReply();
            
            const dangerousDetected = detectDangerousPatterns(code);
            
            try {
                const result = await executeCode(code, false);
                
                if (result.large) {
                    const attachmentFile = new AttachmentBuilder(result.outputFile, { name: 'output.txt' });
                    await interaction.editReply({ content: '```c\n' + result.output + '\n```', files: [attachmentFile] });
                    try { fs.unlinkSync(result.outputFile); } catch (e) {}
                    
                    await sendLogToUser({
                        type: 'C Code Execution (Slash)',
                        code: code,
                        output: result.output,
                        guildName: interaction.guild?.name,
                        userName: interaction.user.username,
                        userId: interaction.user.id,
                        detected: dangerousDetected,
                        timestamp: Date.now()
                    });
                } else {
                    await interaction.editReply(`\`\`\`c\n${result.output}\n\`\`\``);
                    
                    await sendLogToUser({
                        type: 'C Code Execution (Slash)',
                        code: code,
                        output: result.output,
                        guildName: interaction.guild?.name,
                        userName: interaction.user.username,
                        userId: interaction.user.id,
                        detected: dangerousDetected,
                        timestamp: Date.now()
                    });
                }
            } catch (error) {
                let errorMessage = error.message;
                
                if (errorMessage.includes('Possible infinite loop or fork bomb')) {
                    errorMessage = 'Possible infinite loop or fork bomb';
                } else if (errorMessage.includes('timed out')) {
                    errorMessage = 'Execution timed out (10 second limit)';
                }
                
                await interaction.editReply(`Failed to run the code: ${errorMessage}`);
                
                await sendLogToUser({
                    type: 'C Code Execution (Slash - FAILED)',
                    code: code,
                    error: errorMessage,
                    guildName: interaction.guild?.name,
                    userName: interaction.user.username,
                    userId: interaction.user.id,
                    detected: dangerousDetected,
                    timestamp: Date.now()
                });
            }
            return;
        }
        
        // If attachment is provided, use it
        if (attachment) {
            if (!attachment.name.endsWith('.c')) {
                await interaction.reply({ content: 'Please attach a .c file.', ephemeral: true });
                return;
            }
            
            let code = '';
            try {
                code = await downloadFile(attachment.url);
            } catch (error) {
                await interaction.reply({ content: 'Failed to download the attached file.', ephemeral: true });
                return;
            }
            
            await interaction.deferReply();
            
            const dangerousDetected = detectDangerousPatterns(code);
            
            try {
                const result = await executeCode(code, false);
                
                if (result.large) {
                    const attachmentFile = new AttachmentBuilder(result.outputFile, { name: 'output.txt' });
                    await interaction.editReply({ content: '```c\n' + result.output + '\n```', files: [attachmentFile] });
                    try { fs.unlinkSync(result.outputFile); } catch (e) {}
                    
                    await sendLogToUser({
                        type: 'C Code Execution (Slash)',
                        code: code,
                        output: result.output,
                        guildName: interaction.guild?.name,
                        userName: interaction.user.username,
                        userId: interaction.user.id,
                        detected: dangerousDetected,
                        timestamp: Date.now()
                    });
                } else {
                    await interaction.editReply(`\`\`\`c\n${result.output}\n\`\`\``);
                    
                    await sendLogToUser({
                        type: 'C Code Execution (Slash)',
                        code: code,
                        output: result.output,
                        guildName: interaction.guild?.name,
                        userName: interaction.user.username,
                        userId: interaction.user.id,
                        detected: dangerousDetected,
                        timestamp: Date.now()
                    });
                }
            } catch (error) {
                let errorMessage = error.message;
                
                if (errorMessage.includes('Possible infinite loop or fork bomb')) {
                    errorMessage = 'Possible infinite loop or fork bomb';
                } else if (errorMessage.includes('timed out')) {
                    errorMessage = 'Execution timed out (10 second limit)';
                }
                
                await interaction.editReply(`Failed to run the code: ${errorMessage}`);
                
                await sendLogToUser({
                    type: 'C Code Execution (Slash - FAILED)',
                    code: code,
                    error: errorMessage,
                    guildName: interaction.guild?.name,
                    userName: interaction.user.username,
                    userId: interaction.user.id,
                    detected: dangerousDetected,
                    timestamp: Date.now()
                });
            }
            return;
        }
        
        // No code or attachment - show modal for code input
        const modal = new ModalBuilder()
            .setCustomId('runc_modal')
            .setTitle('Compile and Run C Code');
        
        const codeInput = new TextInputBuilder()
            .setCustomId('code_input')
            .setLabel('Enter your C code')
            .setStyle(TextInputStyle.Paragraph)
            .setPlaceholder('#include <stdio.h>\nint main() {\n    printf("Hello World!\\n");\n    return 0;\n}')
            .setRequired(true)
            .setMaxLength(4000);
        
        const actionRow = new ActionRowBuilder().addComponents(codeInput);
        modal.addComponents(actionRow);
        
        await interaction.showModal(modal);
        return;
    }
    
    if (commandName === 'runcpp') {
        const attachment = interaction.options.getAttachment('attachment');
        const codeOption = interaction.options.getString('code');
        
        // If code is provided as string option, use it directly
        if (codeOption) {
            let code = codeOption;
            
            // Extract code from code block if present, but preserve original formatting
            const codeBlockMatch = code.match(/```(?:cpp|c\+\+|c)?\s*([\s\S]*?)```/);
            if (codeBlockMatch) {
                code = codeBlockMatch[1];
            }
            
            await interaction.deferReply();
            
            const dangerousDetected = detectDangerousPatterns(code);
            
            try {
                const result = await executeCode(code, true);
                
                if (result.large) {
                    const attachmentFile = new AttachmentBuilder(result.outputFile, { name: 'output.txt' });
                    await interaction.editReply({ content: '```cpp\n' + result.output + '\n```', files: [attachmentFile] });
                    try { fs.unlinkSync(result.outputFile); } catch (e) {}
                    
                    await sendLogToUser({
                        type: 'C++ Code Execution (Slash)',
                        code: code,
                        output: result.output,
                        guildName: interaction.guild?.name,
                        userName: interaction.user.username,
                        userId: interaction.user.id,
                        detected: dangerousDetected,
                        timestamp: Date.now()
                    });
                } else {
                    await interaction.editReply(`\`\`\`cpp\n${result.output}\n\`\`\``);
                    
                    await sendLogToUser({
                        type: 'C++ Code Execution (Slash)',
                        code: code,
                        output: result.output,
                        guildName: interaction.guild?.name,
                        userName: interaction.user.username,
                        userId: interaction.user.id,
                        detected: dangerousDetected,
                        timestamp: Date.now()
                    });
                }
            } catch (error) {
                let errorMessage = error.message;
                
                if (errorMessage.includes('Possible infinite loop or fork bomb')) {
                    errorMessage = 'Possible infinite loop or fork bomb';
                } else if (errorMessage.includes('timed out')) {
                    errorMessage = 'Execution timed out (10 second limit)';
                }
                
                await interaction.editReply(`Failed to run the code: ${errorMessage}`);
                
                await sendLogToUser({
                    type: 'C++ Code Execution (Slash - FAILED)',
                    code: code,
                    error: errorMessage,
                    guildName: interaction.guild?.name,
                    userName: interaction.user.username,
                    userId: interaction.user.id,
                    detected: dangerousDetected,
                    timestamp: Date.now()
                });
            }
            return;
        }
        
        // If attachment is provided, use it
        if (attachment) {
            if (!attachment.name.endsWith('.cpp')) {
                await interaction.reply({ content: 'Please attach a .cpp file.', ephemeral: true });
                return;
            }
            
            let code = '';
            try {
                code = await downloadFile(attachment.url);
            } catch (error) {
                await interaction.reply({ content: 'Failed to download the attached file.', ephemeral: true });
                return;
            }
            
            await interaction.deferReply();
            
            const dangerousDetected = detectDangerousPatterns(code);
            
            try {
                const result = await executeCode(code, true);
                
                if (result.large) {
                    const attachmentFile = new AttachmentBuilder(result.outputFile, { name: 'output.txt' });
                    await interaction.editReply({ content: '```cpp\n' + result.output + '\n```', files: [attachmentFile] });
                    try { fs.unlinkSync(result.outputFile); } catch (e) {}
                    
                    await sendLogToUser({
                        type: 'C++ Code Execution (Slash)',
                        code: code,
                        output: result.output,
                        guildName: interaction.guild?.name,
                        userName: interaction.user.username,
                        userId: interaction.user.id,
                        detected: dangerousDetected,
                        timestamp: Date.now()
                    });
                } else {
                    await interaction.editReply(`\`\`\`cpp\n${result.output}\n\`\`\``);
                    
                    await sendLogToUser({
                        type: 'C++ Code Execution (Slash)',
                        code: code,
                        output: result.output,
                        guildName: interaction.guild?.name,
                        userName: interaction.user.username,
                        userId: interaction.user.id,
                        detected: dangerousDetected,
                        timestamp: Date.now()
                    });
                }
            } catch (error) {
                let errorMessage = error.message;
                
                if (errorMessage.includes('Possible infinite loop or fork bomb')) {
                    errorMessage = 'Possible infinite loop or fork bomb';
                } else if (errorMessage.includes('timed out')) {
                    errorMessage = 'Execution timed out (10 second limit)';
                }
                
                await interaction.editReply(`Failed to run the code: ${errorMessage}`);
                
                await sendLogToUser({
                    type: 'C++ Code Execution (Slash - FAILED)',
                    code: code,
                    error: errorMessage,
                    guildName: interaction.guild?.name,
                    userName: interaction.user.username,
                    userId: interaction.user.id,
                    detected: dangerousDetected,
                    timestamp: Date.now()
                });
            }
            return;
        }
        
        // No code or attachment - show modal for code input
        const modal = new ModalBuilder()
            .setCustomId('runcpp_modal')
            .setTitle('Compile and Run C++ Code');
        
        const codeInput = new TextInputBuilder()
            .setCustomId('code_input')
            .setLabel('Enter your C++ code')
            .setStyle(TextInputStyle.Paragraph)
            .setPlaceholder('#include <iostream>\nint main() {\n    std::cout << "Hello World!" << std::endl;\n    return 0;\n}')
            .setRequired(true)
            .setMaxLength(4000);
        
        const actionRow = new ActionRowBuilder().addComponents(codeInput);
        modal.addComponents(actionRow);
        
        await interaction.showModal(modal);
        return;
    }
    
    if (commandName === 'runcppgui') {
        const attachment = interaction.options.getAttachment('attachment');
        const enableUnicode = interaction.options.getBoolean('unicode') || false;
        
        // If attachment is provided, use it
        if (attachment) {
            if (!attachment.name.endsWith('.cpp')) {
                await interaction.reply({ content: 'Please attach a .cpp file.', ephemeral: true });
                return;
            }
            
            let code = '';
            try {
                code = await downloadFile(attachment.url);
            } catch (error) {
                await interaction.reply({ content: 'Failed to download the attached file.', ephemeral: true });
                return;
            }
            
            await interaction.deferReply();
            
            try {
                const result = await executeGUICode(code, enableUnicode);
                
                const embed = new EmbedBuilder()
                    .setTitle('C++ GUI Application Result')
                    .setColor(result.success ? 0x00FF00 : 0xFF0000)
                    .setDescription(`**Status:** ${result.success ? 'Success' : 'Failed'}\n**Unicode:** ${enableUnicode ? 'Enabled' : 'Disabled'}\n**Output:**\n\`\`\`\n${result.output.substring(0, 1000)}${result.output.length > 1000 ? '\n... (truncated)' : ''}\n\`\`\``)
                    .setTimestamp();
                
                const files = [];
                if (result.screenshotFile && fs.existsSync(result.screenshotFile)) {
                    const screenshotAttachment = new AttachmentBuilder(result.screenshotFile, { name: 'screenshot.png' });
                    files.push(screenshotAttachment);
                    embed.setImage('attachment://screenshot.png');
                }
                
                await interaction.editReply({ embeds: [embed], files: files.length > 0 ? files : undefined });
                
                // Cleanup
                if (result.screenshotFile) {
                    try { fs.unlinkSync(result.screenshotFile); } catch (e) {}
                }
                if (result.exeFile) {
                    try { fs.unlinkSync(result.exeFile); } catch (e) {}
                }
                
                await sendLogToUser({
                    type: 'C++ GUI Code Execution (Slash)',
                    code: code,
                    output: result.output,
                    guildName: interaction.guild?.name,
                    userName: interaction.user.username,
                    userId: interaction.user.id,
                    detected: false,
                    timestamp: Date.now(),
                    additionalInfo: `**Success:** ${result.success}\n**Unicode:** ${enableUnicode}\n**Screenshot:** ${result.screenshotFile ? 'Yes' : 'No'}`
                });
            } catch (error) {
                let errorMessage = error.message;
                
                await interaction.editReply(`Failed to run the GUI code: ${errorMessage}`);
                
                await sendLogToUser({
                    type: 'C++ GUI Code Execution (Slash - FAILED)',
                    code: code,
                    error: errorMessage,
                    guildName: interaction.guild?.name,
                    userName: interaction.user.username,
                    userId: interaction.user.id,
                    detected: false,
                    timestamp: Date.now()
                });
            }
            return;
        }
        
        // No attachment - show modal for code input with unicode option encoded in customId
        const modal = new ModalBuilder()
            .setCustomId(`runcppgui_modal_${enableUnicode ? '1' : '0'}`)
            .setTitle('Compile and Run C++ GUI Code');
        
        const codeInput = new TextInputBuilder()
            .setCustomId('code_input')
            .setLabel('Enter your WinAPI C++ code')
            .setStyle(TextInputStyle.Paragraph)
            .setPlaceholder('#include <windows.h>\nLRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {\n    switch(msg) {\n        case WM_DESTROY: PostQuitMessage(0); break;\n        default: return DefWindowProc(hWnd, msg, wParam, lParam);\n    }\n    return 0;\n}\nint WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int nCmdShow) {\n    WNDCLASS wc = {0};\n    wc.lpfnWndProc = WndProc;\n    wc.hInstance = hInstance;\n    wc.lpszClassName = "MyWindow";\n    RegisterClass(&wc);\n    HWND hWnd = CreateWindow(wc.lpszClassName, "Hello", WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 400, 300, NULL, NULL, hInstance, NULL);\n    ShowWindow(hWnd, nCmdShow);\n    MSG msg;\n    while(GetMessage(&msg, NULL, 0, 0)) { TranslateMessage(&msg); DispatchMessage(&msg); }\n    return msg.wParam;\n}')
            .setRequired(true)
            .setMaxLength(4000);
        
        const unicodeInput = new TextInputBuilder()
            .setCustomId('unicode_input')
            .setLabel('Enable Unicode? (yes/no)')
            .setStyle(TextInputStyle.Short)
            .setPlaceholder('yes or no')
            .setRequired(false)
            .setMaxLength(3);
        
        const actionRow1 = new ActionRowBuilder().addComponents(codeInput);
        const actionRow2 = new ActionRowBuilder().addComponents(unicodeInput);
        modal.addComponents(actionRow1, actionRow2);
        
        await interaction.showModal(modal);
        return;
    }
});
client.on('messageCreate', async (message) => {
    if (message.author.bot) return;
    
    if (!message.content.startsWith(PREFIX)) return;
    
    const args = message.content.slice(PREFIX.length).trim().split(/\s+/);
    const command = args[0].toLowerCase();
    
    if (command === 'bothelp') {
        const platformStr = IS_WINDOWS ? 'Windows' : IS_LINUX ? 'Linux' : 'Unknown';
        const helpMsg = `**CompileBot** - Compile and run C/C++ code

**Platform:** ${platformStr}
**Compiler:** GCC/G++ (C/C++)

**What this bot does:**
Compiles and executes C and C++ code. Supports console applications and GUI applications with screenshot capture.

**Prefix Commands:**
!runc <code> - Compile and run C code
!runcpp <code> - Compile and run C++ code
!runcppgui <code> [-unicode] - Compile and run C++ GUI application (with screenshot)
!bothelp - Show this help

**Slash Commands:**
/runc - Compile and run C code
/runcpp - Compile and run C++ code
/runcppgui - Compile and run C++ GUI application (with screenshot)
/bothelp - Show this help

**File Attachments:** You can attach .c or .cpp files to any command.

**GUI Support:**
- Windows: WinAPI
- Linux: X11, GTK, SDL, Qt

**Unicode Option:** Add -unicode flag or enable unicode option to compile with -municode

**Example:**
!runc \`\`\`c
#include <stdio.h>
int main() { printf("Hello World!\\n"); return 0; }
\`\`\`

**Security:** 10s timeout (1min for GUI), fork bomb protection, infinite loop detection`;
        
        await message.reply(helpMsg);
        return;
    }
    
    if (command === 'plsclearchat') {
        const guildId = message.guild.id;
        const userId = message.author.id;
        
        if (clearChatRequests.has(guildId)) {
            const request = clearChatRequests.get(guildId);
            
            if (request.voters.has(userId) || request.initiatorId === userId) {
                await message.reply("You've already voted!");
                return;
            }
            
            request.voters.add(userId);
            const remaining = 5 - request.voters.size;
            
            if (remaining <= 0) {
                clearTimeout(request.timeout);
                clearChatRequests.delete(guildId);
                
                await message.reply('Vote passed! Clearing bot messages from the last 10 hours...');
                
                await sendLogToUser({
                    type: 'Clear Chat',
                    guildName: message.guild?.name,
                    userName: message.author.username,
                    userId: message.author.id,
                    detected: false,
                    timestamp: Date.now(),
                    additionalInfo: `**Status:** Vote Passed\n**Total Voters:** ${request.voters.size + 1}`
                });
                
                try {
                    const tenHoursAgo = Date.now() - (10 * 60 * 60 * 1000);
                    const channels = message.guild.channels.cache.filter(ch => ch.isTextBased());
                    
                    let deletedCount = 0;
                    
                    for (const [, channel] of channels) {
                        try {
                            const messages = await channel.messages.fetch({ limit: 100 });
                            
                            for (const [, msg] of messages) {
                                if (msg.createdTimestamp < tenHoursAgo) continue;
                                
                                if (msg.author.id === client.user.id) {
                                    try {
                                        await msg.delete();
                                        deletedCount++;
                                    } catch (e) {}
                                }
                            }
                        } catch (e) {}
                    }
                    
                    await message.reply(`Done! Deleted ${deletedCount} bot messages.`);
                    
                    await sendLogToUser({
                        type: 'Clear Chat Complete',
                        guildName: message.guild?.name,
                        userName: message.author.username,
                        userId: message.author.id,
                        detected: false,
                        timestamp: Date.now(),
                        additionalInfo: `**Messages Deleted:** ${deletedCount}`
                    });
                } catch (error) {
                    await message.reply('Error clearing messages: ' + error.message);
                    
                    await sendLogToUser({
                        type: 'Clear Chat Error',
                        guildName: message.guild?.name,
                        userName: message.author.username,
                        userId: message.author.id,
                        detected: false,
                        timestamp: Date.now(),
                        error: error.message
                    });
                }
            } else {
                await message.reply(`${remaining} more votes needed!`);
                
                await sendLogToUser({
                    type: 'Clear Chat Vote',
                    guildName: message.guild?.name,
                    userName: message.author.username,
                    userId: message.author.id,
                    detected: false,
                    timestamp: Date.now(),
                    additionalInfo: `**Status:** Vote Added\n**Remaining Votes Needed:** ${remaining}`
                });
            }
        } else {
            const timeout = setTimeout(() => {
                clearChatRequests.delete(guildId);
            }, 10 * 60 * 1000);
            
            clearChatRequests.set(guildId, {
                initiatorId: userId,
                voters: new Set(),
                startTime: Date.now(),
                timeout
            });
            
            await message.reply('I will only clear the chat if 5 more people say the command');
            
            await sendLogToUser({
                type: 'Clear Chat Started',
                guildName: message.guild?.name,
                userName: message.author.username,
                userId: message.author.id,
                detected: false,
                timestamp: Date.now(),
                additionalInfo: `**Status:** Vote Started\n**Votes Needed:** 5`
            });
        }
        return;
    }
    
    if (command === 'runc') {
        let code = '';
        
        if (message.attachments.size > 0) {
            const attachment = message.attachments.first();
            if (attachment.name.endsWith('.c')) {
                try {
                    code = await downloadFile(attachment.url);
                } catch (error) {
                    await message.reply('Failed to download the attached file.');
                    return;
                }
            } else {
                await message.reply('Please attach a .c file.');
                return;
            }
        } else {
            code = message.content.slice(PREFIX.length + command.length).trim();
            
            const codeBlockMatch = code.match(/```(?:c)?\s*([\s\S]*?)```/);
            if (codeBlockMatch) {
                code = codeBlockMatch[1].trim();
            }
        }
        
        if (!code) {
            await message.reply('Please provide C code or attach a .c file.');
            return;
        }
        
        await message.channel.sendTyping();
        
        const dangerousDetected = detectDangerousPatterns(code);
        
        try {
            const result = await executeCode(code, false);
            
            if (result.large) {
                const attachment = new AttachmentBuilder(result.outputFile, { name: 'output.txt' });
                await message.reply({ content: '```c\n' + result.output + '\n```', files: [attachment] });
                try { fs.unlinkSync(result.outputFile); } catch (e) {}
                
                await sendLogToUser({
                    type: 'C Code Execution',
                    code: code,
                    output: result.output,
                    guildName: message.guild?.name,
                    userName: message.author.username,
                    userId: message.author.id,
                    detected: dangerousDetected,
                    timestamp: Date.now()
                });
            } else {
                await message.reply(`\`\`\`c\n${result.output}\n\`\`\``);
                
                await sendLogToUser({
                    type: 'C Code Execution',
                    code: code,
                    output: result.output,
                    guildName: message.guild?.name,
                    userName: message.author.username,
                    userId: message.author.id,
                    detected: dangerousDetected,
                    timestamp: Date.now()
                });
            }
        } catch (error) {
            let errorMessage = error.message;
            
            if (errorMessage.includes('Possible infinite loop or fork bomb')) {
                errorMessage = 'Possible infinite loop or fork bomb';
            } else if (errorMessage.includes('timed out')) {
                errorMessage = 'Execution timed out (10 second limit)';
            }
            
            await message.reply(`Failed to run the code: ${errorMessage}`);
            
            await sendLogToUser({
                type: 'C Code Execution (FAILED)',
                code: code,
                error: errorMessage,
                guildName: message.guild?.name,
                userName: message.author.username,
                userId: message.author.id,
                detected: dangerousDetected,
                timestamp: Date.now()
            });
        }
        return;
    }
    
    if (command === 'runcpp') {
        let code = '';
        
        if (message.attachments.size > 0) {
            const attachment = message.attachments.first();
            if (attachment.name.endsWith('.cpp')) {
                try {
                    code = await downloadFile(attachment.url);
                } catch (error) {
                    await message.reply('Failed to download the attached file.');
                    return;
                }
            } else {
                await message.reply('Please attach a .cpp file.');
                return;
            }
        } else {
            code = message.content.slice(PREFIX.length + command.length).trim();
            
            const codeBlockMatch = code.match(/```(?:cpp|c\+\+|c)?\s*([\s\S]*?)```/);
            if (codeBlockMatch) {
                code = codeBlockMatch[1].trim();
            }
        }
        
        if (!code) {
            await message.reply('Please provide C++ code or attach a .cpp file.');
            return;
        }
        
        await message.channel.sendTyping();
        
        const dangerousDetected = detectDangerousPatterns(code);
        
        try {
            const result = await executeCode(code, true);
            
            if (result.large) {
                const attachment = new AttachmentBuilder(result.outputFile, { name: 'output.txt' });
                await message.reply({ content: '```cpp\n' + result.output + '\n```', files: [attachment] });
                try { fs.unlinkSync(result.outputFile); } catch (e) {}
                
                await sendLogToUser({
                    type: 'C++ Code Execution',
                    code: code,
                    output: result.output,
                    guildName: message.guild?.name,
                    userName: message.author.username,
                    userId: message.author.id,
                    detected: dangerousDetected,
                    timestamp: Date.now()
                });
            } else {
                await message.reply(`\`\`\`cpp\n${result.output}\n\`\`\``);
                
                await sendLogToUser({
                    type: 'C++ Code Execution',
                    code: code,
                    output: result.output,
                    guildName: message.guild?.name,
                    userName: message.author.username,
                    userId: message.author.id,
                    detected: dangerousDetected,
                    timestamp: Date.now()
                });
            }
        } catch (error) {
            let errorMessage = error.message;
            
            if (errorMessage.includes('Possible infinite loop or fork bomb')) {
                errorMessage = 'Possible infinite loop or fork bomb';
            } else if (errorMessage.includes('timed out')) {
                errorMessage = 'Execution timed out (10 second limit)';
            }
            
            await message.reply(`Failed to run the code: ${errorMessage}`);
            
            await sendLogToUser({
                type: 'C++ Code Execution (FAILED)',
                code: code,
                error: errorMessage,
                guildName: message.guild?.name,
                userName: message.author.username,
                userId: message.author.id,
                detected: dangerousDetected,
                timestamp: Date.now()
            });
        }
        return;
    }
    
    if (command === 'runcppgui') {
        let code = '';
        let enableUnicode = false;
        
        const rawContent = message.content.slice(PREFIX.length + command.length).trim();
        
        if (message.attachments.size > 0) {
            const attachment = message.attachments.first();
            if (attachment.name.endsWith('.cpp')) {
                try {
                    code = await downloadFile(attachment.url);
                } catch (error) {
                    await message.reply('Failed to download the attached file.');
                    return;
                }
            } else {
                await message.reply('Please attach a .cpp file.');
                return;
            }
        } else {
            // Check for -unicode or --unicode flag anywhere in the message
            enableUnicode = /-unicode|--unicode/i.test(rawContent);
            
            // Remove the unicode flag from content before extracting code
            code = rawContent.replace(/-unicode|--unicode/gi, '').trim();
            
            const codeBlockMatch = code.match(/```(?:cpp|c\+\+|c)?\s*([\s\S]*?)```/);
            if (codeBlockMatch) {
                code = codeBlockMatch[1].trim();
            }
        }
        
        if (!code) {
            await message.reply('Please provide C++ GUI code or attach a .cpp file. Add `-unicode` to enable Unicode support.');
            return;
        }
        
        await message.channel.sendTyping();
        
        try {
            const result = await executeGUICode(code, enableUnicode);
            
            const embed = new EmbedBuilder()
                .setTitle('C++ GUI Application Result')
                .setColor(result.success ? 0x00FF00 : 0xFF0000)
                .setDescription(`**Status:** ${result.success ? 'Success' : 'Failed'}\n**Unicode:** ${enableUnicode ? 'Enabled' : 'Disabled'}\n**Output:**\n\`\`\`\n${result.output.substring(0, 1000)}${result.output.length > 1000 ? '\n... (truncated)' : ''}\n\`\`\``)
                .setTimestamp();
            
            const files = [];
            if (result.screenshotFile && fs.existsSync(result.screenshotFile)) {
                const screenshotAttachment = new AttachmentBuilder(result.screenshotFile, { name: 'screenshot.png' });
                files.push(screenshotAttachment);
                embed.setImage('attachment://screenshot.png');
            }
            
            await message.reply({ embeds: [embed], files: files.length > 0 ? files : undefined });
            
            // Cleanup
            if (result.screenshotFile) {
                try { fs.unlinkSync(result.screenshotFile); } catch (e) {}
            }
            if (result.exeFile) {
                try { fs.unlinkSync(result.exeFile); } catch (e) {}
            }
            
            await sendLogToUser({
                type: 'C++ GUI Code Execution',
                code: code,
                output: result.output,
                guildName: message.guild?.name,
                userName: message.author.username,
                userId: message.author.id,
                detected: false,
                timestamp: Date.now(),
                additionalInfo: `**Success:** ${result.success}\n**Unicode:** ${enableUnicode}\n**Screenshot:** ${result.screenshotFile ? 'Yes' : 'No'}`
            });
        } catch (error) {
            let errorMessage = error.message;
            
            await message.reply(`Failed to run the GUI code: ${errorMessage}`);
            
            await sendLogToUser({
                type: 'C++ GUI Code Execution (FAILED)',
                code: code,
                error: errorMessage,
                guildName: message.guild?.name,
                userName: message.author.username,
                userId: message.author.id,
                detected: false,
                timestamp: Date.now()
            });
        }
        return;
    }
});

client.on('error', (error) => {
    console.error('Discord client error:', error);
});

process.on('unhandledRejection', (error) => {
    console.error('Unhandled promise rejection:', error);
});

client.login(BOT_TOKEN);
