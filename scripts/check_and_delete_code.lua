local code_key = KEYS[1]
local user_id = redis.call('GET', code_key)
if user_id then
    redis.call('DEL', code_key)
end
return user_id
