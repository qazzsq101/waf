require 'config'
function option(args)
	if args == on then
		return true
	end
	if args == off then
		return false
	end
	return true
end
ngxmatch=ngx.re.match
unescape=ngx.unescape_uri
all_switch = option(All_switch)
cc_switch = option(Cc_switch)
rule_path = Rule_path
attack_log = option(Attack_log)
log_dir = Log_dir
http_x_forwarded_for = option(Http_x_forwarded_for)

function split(s, delim)
       	if type(delim) ~= "string" or string.len(delim) <= 0 then
       		return
       	end
       	local start = 1
       	local t = {}
       	while true do
       		local pos = string.find (s, delim, start, true) -- plain find
       		if not pos then
       			break
       		end
       		table.insert (t, string.sub (s, start, pos - 1))
       		start = pos + string.len (delim)
       	end
       	table.insert (t, string.sub (s, start))
       	return t
end

function GetClientIp()
	local Ip=""
	if http_x_forwarded_for == false then
		Ip  = ngx.var.remote_addr
	end
	if http_x_forwarded_for == true and ngx.var.http_x_forwarded_for ~= nil and ngx.var.http_x_forwarded_for ~= "" then
		Ip = split(ngx.var.http_x_forwarded_for,",")[1]
	else
		Ip  = ngx.var.remote_addr
	end
        return  Ip
end

function Log(method,url,data,ruletag)
	if attack_log then
		local Ip = GetClientIp()
		local Ua = ngx.var.http_user_agent
		local ServerName=""
		local Line=""
		if ngx.var.server_name ~= nil and ngx.var.server_name ~= "" then
			ServerName=ngx.var.server_name
		else 
			ServerName=ngx.var.server_addr
		end
		local Time=ngx.localtime()
		if Ua  then
			Line = "["..Time.."]`"..Ip.."`"..ServerName.."`"..url.."`"..method.."`"..Ua.."`"..data.."`"..ruletag.."\"\n"
 		else
			Line = "["..Time.."]`"..Ip.."`"..ServerName.."`"..url.."`"..method.."`".."".."`"..data.."`"..ruletag.."\"\n"
		end
		local filename = log_dir..ServerName.."_"..ngx.today()..".log"
		local fd = io.open(filename,"ab")
		if fd == nil then return end
		fd:write(Line)
		fd:flush()
		fd:close()
		return true
	end
	return false
end

function ReadRule(var)
    local file = io.open(rule_path..var,"r")
    if file==nil then
        return
    end
    local t = {}
    for line in file:lines() do
        table.insert(t,line)
    end
    file:close()
    return(t)
end

urlrules=ReadRule('deny_rule')
uarules=ReadRule('user-agent')
wturlrules=ReadRule('whiteurl')
postrules=ReadRule('deny_rule')
ckrules=ReadRule('deny_rule')

function Say_html()
        ngx.header.content_type = "text/html"
        ngx.status = ngx.HTTP_FORBIDDEN
        ngx.say(html)
        ngx.exit(ngx.status)
end

function WhiteUrl()
	if all_switch and  wturlrules ~=nil then
		local rule
		for _,rule in pairs(wturlrules) do
			if ngxmatch(ngx.var.uri,rule,"isjo") then
				return true 
		end
	end
    end
    return false
end

function DenyUrl()
	if all_switch then
		local rule
		for _,rule in pairs(urlrules) do
			if rule ~="" and ngxmatch(unescape(ngx.var.request_uri),rule,"isjo") then
				Log(ngx.var.request_method,ngx.var.request_uri,"-",rule)
				Say_html()
				return true
			end
		end
	end
	return false
end

function DenyUa()
	if all_switch then
		local ua = ngx.var.http_user_agent
		local rule
		if ua ~= nil then
			for _,rule in pairs(uarules) do
				if rule ~="" and ngxmatch(ua,rule,"isjo") then
					Log('UA',ngx.var.request_uri,"-",rule)
					Say_html()
					return true
				end
			end
		end
	end
    	return false
end

function DenyCookie()
    local ck = ngx.var.http_cookie
    if all_switch and ck~= nil then
        for _,rule in pairs(ckrules) do
            if rule ~="" and ngxmatch(ck,rule,"isjo") then
                Log('Cookie',ngx.var.request_uri,"-",rule)
                Say_html()
            return true
            end
        end
    end
    return false
end

function WhiteIp()
	if all_switch and next(ipWhitelist) ~= nil then
		local ip
		for _,ip in pairs(ipWhitelist) do
			if GetClientIp()==ip then
				return true
			end
		end
	end
	return false
end

function BlockIp()
	if all_switch and next(ipBlocklist) ~= nil then
		local ip
		for _,ip in pairs(ipBlocklist) do
			if GetClientIp()==ip then
				ngx.exit(403)
				return true
			end
		end
	end
	return false
end

function DenyPost()
	if all_switch and ngx.var.request_method == "POST" then
		ngx.req.read_body()
		local rule
		if ngx.req.get_body_data() ~= "" and ngx.req.get_body_data() ~= nil then
			for _,rule in pairs(postrules) do
				if rule ~="" and ngxmatch(ngx.req.get_body_data(),rule,"isjo") then
					Log('POST',ngx.var.request_uri,"-",rule)
					Say_html()
					return true
				end
			end
		end
	end
	return false
end
