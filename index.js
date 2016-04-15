var spawn = require('child_process').spawn;
var lazy = require('lazy');

exports.allow = function (rule) {
    rule.target = 'ACCEPT';
    if (!rule.action) rule.action = '-A';
    newRule(rule);
}

exports.drop = function (rule) {
    rule.target = 'DROP';
    if (!rule.action) rule.action = '-A';
    newRule(rule);
}

exports.reject = function (rule) {
    rule.target = 'REJECT';
    if (!rule.action) rule.action = '-A';
    newRule(rule);
}

exports.list = function(chain, table, cb) {
    
    if (!cb && typeof table == "function") {
        cb=table;
        table=null;
    }
    var rule = {
        list : true,
        chain : chain,
        action : '-L',
        sudo : true,
        params: ['--line-numbers']
    };
    if (table) rule.table=table;

    lazy(iptables(rule).stdout)
        .lines
        .map(String)
        .skip(2)
        .map(function (line) {
            // packets, bytes, target, pro, opt, in, out, src, dst, opts
            var fields = line.trim().split(/\s+/, 9);
            return {
                parsed : {
                    line : fields[0],
                    packets : fields[1],
                    bytes : fields[2],
                    target : fields[3],
                    protocol : fields[4],
                    opt : fields[5],
                    in : fields[6],
                    out : fields[7],
                    src : fields[8],
                    dst : fields[9]
                },
                raw : line.trim()
            };
        })
        .join(function (rules) {
            cb(rules);
        })
}

exports.newRule = newRule;
exports.deleteRule = deleteRule;

function iptables (rule) {
    var args = iptablesArgs(rule);

    var cmd = 'iptables';
    if (rule.sudo) {
        cmd = 'sudo';
        args = ['iptables'].concat(args);
    }

    var proc = spawn(cmd, args);
    proc.stderr.on('data', function (buf) {
        console.error(buf.toString());
    });
    return proc;
}

function iptablesArgs (rule) {
    var args = [];

    if (rule.table) args = args.concat(["-t", rule.table]);

    if (!rule.chain) rule.chain = 'INPUT';

    if (rule.chain) args = args.concat([rule.action, rule.chain]);
    if (rule.protocol) args = args.concat(["-p", rule.protocol]);
    if (rule.src) args = args.concat(["--src", rule.src]);
    if (rule.dst) args = args.concat(["--dst", rule.dst]);
    if (rule.sport) args = args.concat(["--sport", rule.sport]);
    if (rule.dport) args = args.concat(["--dport", rule.dport]);
    if (rule.in) args = args.concat(["-i", rule.in]);
    if (rule.out) args = args.concat(["-o", rule.out]);
    if (rule.target) args = args.concat(["-j", rule.target]);
    if (rule.list) args = args.concat(["-n", "-v"]);
    if (rule.params && Array.isArray(rule.params)) args = args.concat(rule.params);

    return args;
}

function newRule (rule) {
    iptables(rule);
}

function deleteRule (rule) {
    rule.action = '-D';
    iptables(rule);
}

