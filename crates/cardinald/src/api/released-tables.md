
#### 1–29: The service, this device, and the person's devices

| # | Request | Arguments | Reply |
|---|---|---|---|
| 1 | `hello` |  | 2 `api` uint, 3 `version` text |
| 2 | `status` | 1 `after` uint, 2 `limit` uint | 2 `bluetooth` *bluetooth*, 3 `carrying_calls` uint, 4 `conditions` *conditions*, 5 `conflicts` uint, 6 `copies` *copies*, 7 `devices` [*device*], 8 `files_ready` bool, 9 `home` text, 10 `hosts` uint, 11 `identity` bytes, 12 `identity_id` bytes, 13 `inspection` *inspection*, 14 `left_behind` [text], 15 `listen` text, 16 `mount` text, 17 `mount_unavailable` text, 18 `mounted` text, 19 `moved_from` uint, 20 `name` text, 21 `network` *network*, 22 `not_saved` uint, 23 `not_saved_undone` uint, 24 `old` *old versions*, 25 `pairing` *pairing*, 26 `peers` [text], 27 `pending_changes` bool, 28 `progress` *progress*, 29 `read_markers` bool, 30 `removed` bool, 31 `retention` text, 32 `router` *router*, 33 `spaces` [*space*], 34 `uptime_s` uint, 35 `more` bool, 36 `next` uint, 37 `redial` *redial*, 38 `always_on` [text] |
| 3 | `watch` | 1 `window` bool |  |
| 4 | `stop` † |  |  |
| 5 | `reload` † |  |  |
| 6 | `conditions` | 1 `plugged_in` bool, 2 `metered` bool | 2 `helps` bool, 3 `metered` bool, 4 `plugged_in` bool |
| 7 | `network-changed` | 1 `why` text | 2 `checking` uint |
| 8 | `setup-begin` |  | 2 `ask` [uint], 3 `words` [text] |
| 9 | `setup-finish` | 1 `name` text, 2 `answers` [text], 3 `device` text | 2 `device` text, 3 `name` text |
| 10 | `me` | 1 `name` text | 2 `name` text, 3 `set` bool |
| 11 | `devices` | 1 `after` uint, 2 `limit` uint | 2 `devices` [*device*], 3 `more` bool, 4 `next` uint |
| 12 | `device-rename` | 1 `device` ref, 2 `name` text | 2 `key` bytes, 3 `name` text |
| 13 | `remove-device` † | 1 `who` ref, 2 `lost` bool, 3 `words` text | 2 `dropped` uint, 3 `name` text |
| 14 | `pair-show` | 1 `admin` bool (no longer used), 2 `device` text | 2 `addrs` [text], 3 `code` text |
| 15 | `pair-status` |  | 2 `admin` text, 3 `code` text, 4 `error` text, 5 `files` bool, 6 `state` text, 7 `power` text |
| 16 | `pair-type` | 1 `code` text, 2 `at` text, 3 `admin` bool, 4 `words` text, 5 `device` text | 2 `name` text |

#### 30–69: People, conversations and invitations

| # | Request | Arguments | Reply |
|---|---|---|---|
| 30 | `contacts` † | 1 `all` bool, 2 `after` uint, 3 `limit` uint | 2 `contacts` [*contact*], 3 `more` bool, 4 `next` uint |
| 31 | `contact` | 1 `who` ref, 2 `setting` text, 3 `name` text, 4 `picture` text, 5 `category` text, 6 `host` text | 2 `category` text, 3 `name` text, 4 `own` bool, 5 `picture` text, 6 `reach` [*group shown*], 7 `suggested` text, 8 `named` text |
| 32 | `contact-status` | 1 `who` ref, 2 `look` bool, 3 `at` text, 4 `after` uint, 5 `limit` uint | 2 `devices` [*contact's device*], 3 `direct_sessions` bool, 4 `identity` bytes, 5 `in_use_for_s` uint, 6 `introductions` bool, 7 `last_look` [*step*], 8 `look_every_s` uint, 9 `looked_for` text, 10 `looked_s_ago` uint, 11 `looking` bool, 12 `looking_since` uint, 13 `looks_without_session` uint, 14 `name` text, 15 `nearby` *nearby*, 16 `nearby_tries` [*step*], 17 `own` bool, 18 `refused` bool, 19 `router` *router*, 20 `sessions` [*step*], 21 `suggested` text, 22 `their_reach` [*reach seen*], 23 `trusted` bool, 24 `your_reach` [*reach seen*], 25 `more` bool, 26 `next` uint |
| 33 | `conversations` | 1 `after` uint, 2 `limit` uint | 2 `conversations` [*conversation*], 3 `more` bool, 4 `next` uint |
| 34 | `messages` | 1 `who` ref, 2 `group` ref, 3 `before` ref, 4 `limit` uint | 2 `group` bytes, 3 `messages` [*message*], 4 `name` text, 5 `more` bool, 6 `next` bytes |
| 35 | `say` | 1 `who` ref, 2 `text` text, 3 `reply_to` ref, 4 `attach` [text], 5 `group` ref | 2 `reachable` bool |
| 36 | `save-attachment` | 1 `who` ref, 2 `id` ref, 3 `index` uint, 4 `to` text, 5 `group` ref | 2 `path` text, 3 `size` uint |
| 37 | `edit-message` | 1 `who` ref, 2 `id` ref, 3 `text` text, 4 `group` ref |  |
| 38 | `delete-message` | 1 `who` ref, 2 `id` ref, 3 `group` ref |  |
| 39 | `react` | 1 `who` ref, 2 `id` ref, 3 `text` text, 4 `group` ref |  |
| 40 | `mark-read` | 1 `who` ref, 2 `group` ref | 2 `kept` bool, 3 `marked` bool, 4 `why` text |
| 41 | `read-markers` † | 1 `on` bool | 2 `on` bool |
| 42 | `invite` | 1 `address` text, 2 `name` text, 3 `hosts_only` bool, 4 `no_introductions` bool | 2 `code` text |
| 43 | `accept` | 1 `code` text, 2 `name` text, 3 `via` text, 4 `hosts_only` bool, 5 `no_introductions` bool, 6 `for` ref | 2 `name` text, 3 `recovery_of` bytes |
| 44 | `invitations` | 1 `after` uint, 2 `limit` uint | 2 `invitations` [*invitation*], 3 `more` bool, 4 `next` uint |
| 45 | `cancel-invitation` | 1 `id` ref |  |
| 46 | `introductions` | 1 `after` uint, 2 `limit` uint | 2 `introductions` [*introduction*], 3 `more` bool, 4 `next` uint |
| 47 | `introduce` | 1 `who` ref, 2 `to` ref, 3 `note` text |  |
| 48 | `introduction-accept` | 1 `id` ref | 2 `name` text, 3 `recovery_of` bytes |
| 49 | `introduction-decline` | 1 `id` ref |  |

#### 70–99: Groups

| # | Request | Arguments | Reply |
|---|---|---|---|
| 70 | `groups` | 1 `after` uint, 2 `limit` uint | 2 `groups` [*group*], 3 `offers` [*offer*], 4 `more` bool, 5 `next` uint, 6 `rejoin` [*rejoin*] |
| 71 | `group-create` | 1 `name` text, 2 `people` [ref] | 2 `group` bytes, 3 `name` text |
| 72 | `group-join` | 1 `group` ref, 2 `reach` bool | 2 `group` bytes, 3 `name` text, 4 `shared` bool, 5 `waiting` bool |
| 73 | `group-decline` | 1 `group` ref |  |
| 74 | `group-leave` | 1 `group` ref, 2 `admins` [ref], 3 `anyway` bool | 2 `admins` [text] |
| 75 | `group-reach` | 1 `group` ref, 2 `share` bool, 3 `host` text | 2 `shared` bool, 3 `waiting` bool, 4 `taken_out` bool |
| 76 | `group-add` | 1 `group` ref, 2 `people` [ref], 3 `shown` text |  |
| 77 | `group-remove` | 1 `group` ref, 2 `who` ref | 2 `group` bytes, 3 `left_out` [bytes], 4 `was` bytes |
| 78 | `group-members` | 1 `group` ref, 2 `after` uint, 3 `limit` uint | 2 `group` bytes, 3 `members` [*member*], 4 `name` text, 5 `more` bool, 6 `next` uint |
| 79 | `group-set` | 1 `group` ref, 2 `name` text, 3 `introductions` bool |  |
| 80 | `group-member` | 1 `group` ref, 2 `who` ref, 3 `shown` text, 4 `introduce` bool |  |
| 81 | `group-connect` | 1 `group` ref, 2 `who` ref, 3 `note` text | 2 `asked` bool |
| 82 | `group-role` † | 1 `group` ref, 2 `who` ref, 3 `role` text | 2 `group` bytes, 3 `was` bytes |
| 83 | `group-post-again` † | 1 `group` ref | 2 `posted` uint |
| 84 | `group-moved-seen` † | 1 `group` ref |  |
| 85 | `group-confirm-move` | 1 `group` ref, 2 `moves` [bytes], 3 `to` [bytes] | 2 `kept` uint |
| 86 | `group-leaving` | 1 `group` ref | 2 `admins` [text], 3 `choose_admin` bool, 4 `group` bytes, 5 `name` text, 6 `relayed_for` [*relayed for*] |
| 87 | `group-rejoin` | 1 `group` ref | 2 `group` bytes, 3 `name` text |

#### 100–119: Calls and the clipboard

| # | Request | Arguments | Reply |
|---|---|---|---|
| 100 | `call` |  | 2 `call` *call*, 3 `ended` *call ended* |
| 101 | `call-start` | 1 `who` ref, 2 `group` ref, 3 `formats` [bytes], 4 `format_names` [text] |  |
| 102 | `call-answer` | 1 `formats` [bytes], 2 `format_names` [text] |  |
| 103 | `call-end` |  |  |
| 104 | `call-media` |  |  |
| 105 | `clip-copy` | 1 `text` text | 2 `devices` uint |
| 106 | `clip` |  | 2 `from` text, 3 `here` bool, 4 `seconds` uint, 5 `text` text |

#### 120–149: The one folder

| # | Request | Arguments | Reply |
|---|---|---|---|
| 120 | `files` | 1 `path` text, 2 `after` uint, 3 `limit` uint | 2 `files` [*file*], 3 `path` text, 4 `place` *place*, 5 `more` bool, 6 `next` uint |
| 121 | `mkdir` | 1 `path` text | 2 `path` text |
| 122 | `move` | 1 `from` text, 2 `to` text | 2 `path` text |
| 123 | `remove` | 1 `path` text | 2 `path` text |
| 124 | `copy` | 1 `from` text, 2 `to` text | 2 `path` text |
| 125 | `put` | 1 `from` text, 2 `to` text | 2 `path` text |
| 126 | `save` | 1 `path` text, 2 `to` text, 3 `version` uint | 2 `path` text, 3 `size` uint |
| 127 | `write` | 1 `from` text, 2 `path` text | 2 `path` text |
| 128 | `share` | 1 `who` ref, 2 `paths` [text], 3 `text` text, 4 `group` ref | 2 `message` bool, 3 `path` text |
| 129 | `mount` † | 1 `path` text | 2 `path` text |
| 130 | `unmount` † |  |  |
| 131 | `flush` † |  | 2 `entries` uint |
| 132 | `conflicts` † | 1 `after` uint, 2 `limit` uint | 2 `conflicts` [*conflict*], 3 `more` bool, 4 `next` uint |
| 133 | `history` | 1 `path` text, 2 `after` uint, 3 `limit` uint | 2 `path` text, 3 `versions` [*version*], 4 `more` bool, 5 `next` uint |
| 134 | `restore` | 1 `path` text, 2 `version` uint | 2 `path` text, 3 `version` uint |
| 135 | `pin` † | 1 `path` text | 2 `on_demand` bool, 3 `path` text |
| 136 | `unpin` † | 1 `path` text | 2 `on_demand` bool, 3 `path` text |
| 137 | `retention` † | 1 `mode` text | 2 `retention` text |
| 138 | `keep-old` † | 1 `keep` text, 2 `space` ref | 2 `keep` text |
| 139 | `free-space` † | 1 `dry_run` bool, 2 `unnamed` bool, 3 `delete` bool | 2 `bytes` uint, 3 `deleted` bool, 4 `left` uint, 5 `objects` uint, 6 `only_here` *only here*, 7 `unchecked` bool, 8 `unsure` [text] |
| 140 | `space-usage` † | 1 `after` uint, 2 `limit` uint | 2 `spaces` [*space usage*], 3 `more` bool, 4 `next` uint |
| 141 | `history-empty` † | 1 `space` ref | 2 `bytes` uint, 3 `left` uint, 4 `objects` uint |

#### 150–179: Guardians and recovery

| # | Request | Arguments | Reply |
|---|---|---|---|
| 150 | `guardians` † |  | 2 `asked` [text], 3 `changes` [*guardian change*], 4 `copy_full` [text], 5 `data` bool, 6 `delay` uint, 7 `delay_text` text, 8 `frozen` bool, 9 `guardians` uint, 10 `names` [text], 11 `ready` [text], 12 `recoveries` [*recovery*], 13 `threshold` uint |
| 151 | `guardians-set` † | 1 `who` [ref], 2 `threshold` uint, 3 `delay` uint, 4 `words` text | 2 `delay` uint, 3 `delay_text` text, 4 `names` [text], 5 `pending` bool, 6 `threshold` uint |
| 152 | `guardians-object` † | 1 `fingerprint` text |  |
| 153 | `guardians-ask` † | 1 `who` ref | 2 `name` text |
| 154 | `guarding` † |  | 2 `accepted` [text], 3 `asked` [text], 4 `guarding` [*guarded*], 5 `named_in_change` [text], 6 `now_ms` uint, 7 `no_longer_needed` [*no longer needed*] |
| 155 | `guarding-invite` † | 1 `who` ref, 2 `at` text | 2 `code` text, 3 `name` text |
| 156 | `guarding-accept` † | 1 `who` ref | 2 `already` bool, 3 `name` text, 4 `persona` bytes |
| 157 | `guarding-confirm-change` † | 1 `who` ref, 2 `fingerprint` text, 3 `understood` bool | 2 `accepted` [text], 3 `asked` [text], 4 `guarding` [*guarded*], 5 `named_in_change` [text], 6 `now_ms` uint, 7 `no_longer_needed` [*no longer needed*] |
| 158 | `guarding-never` † | 1 `who` ref, 2 `fingerprint` text | 2 `accepted` [text], 3 `asked` [text], 4 `guarding` [*guarded*], 5 `named_in_change` [text], 6 `now_ms` uint, 7 `no_longer_needed` [*no longer needed*] |
| 159 | `guarding-caution` † | 1 `who` ref | 2 `caution` text, 3 `name` text |
| 160 | `guarding-endorse` † | 1 `who` ref, 2 `fingerprint` text, 3 `understood` bool | 2 `accepted` [text], 3 `asked` [text], 4 `guarding` [*guarded*], 5 `named_in_change` [text], 6 `now_ms` uint, 7 `no_longer_needed` [*no longer needed*] |
| 161 | `guarding-confirm` † | 1 `who` ref, 2 `fingerprint` text, 3 `understood` bool | 2 `accepted` [text], 3 `asked` [text], 4 `guarding` [*guarded*], 5 `named_in_change` [text], 6 `now_ms` uint, 7 `no_longer_needed` [*no longer needed*] |
| 162 | `recover` † |  | 2 `asked` bool, 3 `confirmed` uint, 4 `endorsed` uint, 5 `fingerprint` text, 6 `guardians` uint, 7 `held` uint, 8 `helper` bool, 9 `identity` bytes, 10 `in_effect` bool, 11 `lost_at` uint, 12 `lost_devices` [*lost device*], 13 `pair_again` [*pair again*], 14 `proposed` uint, 15 `successions` [*succession*] (no longer used), 16 `threshold` uint, 17 `under_way` bool, 18 `finished` bool, 19 `words` text, 20 `kept_changes` [*kept change*] |
| 163 | `recover-start` † | 1 `code` text, 2 `identity` ref | 2 `fingerprint` text, 3 `identity` bytes |
| 164 | `recover-invite` † | 1 `at` text | 2 `code` text, 3 `fingerprint` text |
| 165 | `recover-keep-succession` † (no longer answered) | 1 `id` text, 2 `keep` bool | 2 `answered` uint, 3 `kept` bool |
| 166 | `recover-lost-at` † | 1 `lost_at` uint | 2 `lost_devices` [*lost device*] |
| 167 | `recover-cancel` † |  | 2 `fingerprint` text |
| 168 | `recover-finish` † | 1 `without_account` bool, 2 `lost_at` uint | 2 `account` bool, 3 `lost_devices` [*lost device*], 4 `pair_again` [*pair again*], 5 `words` text |
| 169 | `keep-work` † | 1 `name` text, 2 `up_to` text | 2 `kept` uint, 3 `set_aside` [*set aside*] |
| 170 | `recovery-check` † | 1 `words` text |  |
| 171 | `recovery-sheet` † |  | 2 `hosts` [*host*] |
| 172 | `restore-from-host` † | 1 `words` text, 2 `at` text, 3 `key` text (no longer used), 4 `key` bytes | 2 `at` text |
| 173 | `recover-undo` † | 1 `to` bytes | 2 `group` bytes, 3 `kept_changes` [*kept change*] |
| 174 | `recover-kept-seen` † | 1 `to` [bytes] | 2 `kept_changes` [*kept change*] |

#### 180–199: Networks, hosts and peers

| # | Request | Arguments | Reply |
|---|---|---|---|
| 180 | `router` † | 1 `on` bool, 2 `this_device` bool | 2 `error` text, 3 `everywhere` bool, 4 `external` text, 5 `named` [text], 6 `network` *network*, 7 `on` bool, 8 `protocol` text, 9 `seconds_left` uint, 10 `this_device` bool |
| 181 | `bluetooth` † | 1 `mode` text | 2 `available` bool, 3 `channels_in` uint, 4 `error` text, 5 `mode` text, 6 `on` bool, 7 `psm` uint, 8 `radio` text, 9 `recognized` uint, 10 `seen` uint, 11 `why_not` text, 12 `windows` uint, 13 `too_old` bool |
| 182 | `network` † | 1 `mine` bool, 2 `name` text | 2 `answered` bool, 3 `ask` bool, 4 `known` bool, 5 `mine` bool, 6 `name` text, 7 `router` text, 8 `routers` bool |
| 183 | `host` † | 1 `addresses` [text] | 2 `hosts` [*host*], 3 `warnings` [text] |
| 184 | `host-off` † |  | 2 `hosts` [*host*] |
| 185 | `peer-add` † | 1 `addr` text | 2 `addr` text |
| 186 | `peer-remove` † | 1 `addr` text |  |
| 187 | `peer-list` † | 1 `after` uint, 2 `limit` uint | 2 `peers` [*peer*], 3 `more` bool, 4 `next` uint |
| 188 | `host-offer` | 1 `who` ref, 2 `devices` [text], 3 `envelopes` uint, 4 `relay_mb` uint | 2 `devices` [text], 3 `sees` text, 4 `on` [*hostable*] |
| 189 | `host-accept` | 1 `who` ref | 2 `sees` text |
| 190 | `host-end` | 1 `who` ref | 2 `ended` bool |
| 191 | `hosting` |  | 2 `can` [text], 3 `hosting` [*hosting*], 4 `why_not` text, 5 `devices` [*hostable*] |

#### 200–219: Inspection and measuring

| # | Request | Arguments | Reply |
|---|---|---|---|
| 200 | `inspect-on` † | 1 `minutes` uint | 2 `token` bytes, 3 `until` uint |
| 201 | `inspect-off` † |  | 2 `was_on` bool |
| 202 | `inspect` † | 1 `token` ref, 2 `after` uint, 3 `limit` uint | 2 `device` *this device*, 3 `identity` *identity*, 4 `others` [*other log*], 5 `spaces` [*space held*], 6 `store` *store*, 7 `version` text, 8 `more` bool, 9 `next` uint |
| 203 | `inspect-identity` † | 1 `token` ref, 2 `who` ref, 3 `entry` ref, 4 `path` [int or text], 5 `value_bytes` uint, 6 `items` uint, 7 `after` uint, 8 `limit` uint | 2 `attached` [*attached log*], 3 `entries` [*identity entry*], 4 `id` bytes, 5 `stalled` [bytes], 6 `value` *value*, 7 `more` bool, 8 `next` uint |
| 204 | `inspect-space` † | 1 `token` ref, 2 `space` ref, 3 `value_bytes` uint, 4 `items` uint, 5 `after` uint, 6 `limit` uint | 2 `account` bool, 3 `bytes` uint, 4 `conflicts` uint, 5 `created` uint, 6 `creator` bytes, 7 `current_epoch` bytes, 8 `entries` uint, 9 `epochs` [*epoch*], 10 `files` bool, 11 `heads` [bytes], 12 `id` bytes, 13 `kinds` [*kind count*], 14 `label` text, 15 `members` [*space member*], 16 `my_role` uint, 17 `nodes` uint, 18 `opened` bool, 19 `owner` bytes, 20 `pending` uint, 21 `policy` *policy*, 22 `profile` kind, 23 `reach` [*reach node*], 24 `rejected` uint, 25 `root` *root*, 26 `sealed` uint, 27 `stats` *stats*, 28 `successor` bytes, 29 `unwitnessed` uint, 30 `valid` uint, 31 `more` bool, 32 `next` uint |
| 205 | `inspect-entries` † | 1 `token` ref, 2 `space` ref, 3 `view` text, 4 `offset` uint (no longer used), 5 `count` uint (no longer used), 6 `after` uint, 7 `limit` uint | 2 `entries` [*entry*], 3 `offset` uint (no longer used), 4 `pending` uint, 5 `total` uint, 6 `more` bool, 7 `next` uint |
| 206 | `inspect-entry` † | 1 `token` ref, 2 `space` ref, 3 `entry` ref, 4 `sealed_id` ref, 5 `path` [int or text], 6 `value_bytes` uint, 7 `items` uint, 8 `after` uint, 9 `limit` uint | 2 `accepted` bool, 3 `children` [bytes], 4 `entry` bytes, 5 `header` *value*, 6 `ops` [*op*], 7 `position` uint, 8 `sealed` *value*, 9 `sealed_id` bytes, 10 `signatures` [*signature*], 11 `valid` bool, 12 `weigh` *weight*, 13 `value` *value*, 14 `more` bool, 15 `next` uint |
| 207 | `inspect-nodes` † | 1 `token` ref, 2 `space` ref, 3 `kind` kind, 4 `parent` ref, 5 `offset` uint (no longer used), 6 `count` uint (no longer used), 7 `after` uint, 8 `limit` uint | 2 `nodes` [*node*], 3 `offset` uint (no longer used), 4 `total` uint, 5 `more` bool, 6 `next` uint |
| 208 | `inspect-node` † | 1 `token` ref, 2 `space` ref, 3 `node` ref, 4 `path` [int or text], 5 `value_bytes` uint, 6 `items` uint, 7 `after` uint, 8 `limit` uint | 2 `bytes` uint, 3 `children` uint, 4 `created` uint, 5 `created_in` bytes, 6 `creator` bytes, 7 `delete_conflict` bool, 8 `deleted` bool, 9 `fields` [[uint]], 10 `history` [*node history*], 11 `id` bytes, 12 `kind` kind, 13 `name` text, 14 `parent` bytes, 15 `position` uint, 16 `special` text, 17 `values` [*node field*], 18 `value` *value*, 19 `more` bool, 20 `next` uint |
| 209 | `debug-tree` † | 1 `after` uint, 2 `limit` uint | 2 `deleted` uint, 3 `epoch` bytes, 4 `heads` bytes, 5 `items` [*tree item*], 6 `mounted` bool, 7 `pending` bool, 8 `settle` uint, 9 `state` bytes, 10 `stuck` [*stuck item*], 11 `unshown` [*unshown node*], 12 `more` bool, 13 `next` uint |
| 210 | `speedtest` † | 1 `device` ref | 2 `device` text, 3 `ms` uint, 4 `receive` uint, 5 `received_bytes` uint, 6 `rtt_median_us` uint, 7 `rtt_min_us` uint, 8 `send` uint, 9 `sent_bytes` uint |

#### 220–239: Applications

| # | Request | Arguments | Reply |
|---|---|---|---|
| 220 | `app-questions` | 1 `after` uint, 2 `limit` uint | 2 `questions` [*app question*], 3 `more` bool, 4 `next` uint |
| 221 | `app-answer` | 1 `id` uint, 2 `yes` bool, 3 `people` [ref], 4 `role` text |  |
| 222 | `approvals` | 1 `after` uint, 2 `limit` uint | 2 `approvals` [*approval*], 3 `more` bool, 4 `next` uint |
| 223 | `approval-revoke` | 1 `id` ref |  |
| 224 | `app-offers` | 1 `after` uint, 2 `limit` uint | 2 `offers` [*app offer*], 3 `more` bool, 4 `next` uint |
| 225 | `app-join` | 1 `space` ref | 2 `space` bytes, 3 `name` text |
| 226 | `wake` |  | 2 `checking` uint |
| 227 | `deleted` | 1 `path` text, 2 `after` uint, 3 `limit` uint, 4 `hidden` bool | 2 `files` [*deleted file*], 3 `path` text, 4 `more` bool, 5 `next` uint |
| 228 | `undelete` | 1 `path` text, 2 `id` ref | 2 `id` bytes, 3 `path` text |

#### What the program says

| Asked | Reply |
|---|---|
| `--store` | 2 `holds` *data held*, 3 `refusal` text, 4 `store` text, 5 `written_by` text |
| `--clear` |  |

#### What an error says

2 `at` uint, 3 `id` bytes

#### Records

| Record | Fields |
|---|---|
| *app offer* | 1 `application` text, 2 `from` text, 3 `name` text, 4 `sentence` text, 5 `space` bytes |
| *app question* | 1 `asks` text, 2 `id` uint, 3 `name` text, 4 `program` text, 5 `role` text, 6 `what` text |
| *approval* | 1 `change` bool, 2 `covers` text, 3 `device` text, 4 `family` bytes, 5 `id` bytes, 6 `name` text, 7 `program` text, 8 `revoked` bool, 9 `this_device` bool |
| *attached log* | 1 `bytes` uint, 2 `entries` uint, 3 `id` bytes |
| *attachment* | 1 `name` text, 2 `size` uint, 3 `type` text |
| *bluetooth* | 1 `available` bool, 2 `channels_in` uint, 3 `error` text, 4 `mode` text, 5 `on` bool, 6 `psm` uint, 7 `radio` text, 8 `recognized` uint, 9 `seen` uint, 10 `why_not` text, 11 `windows` uint, 12 `too_old` bool |
| *call* | 1 `frames` *frames*, 2 `group` bytes, 3 `id` bytes, 4 `linked` uint, 5 `name` text, 6 `offered` [bytes], 7 `people` uint, 8 `picture` text, 9 `seconds` uint, 10 `state` text, 11 `taken` [bytes], 12 `who` bytes, 13 `voices` [*voice*], 14 `they_take` [bytes], 15 `camera` bool |
| *call ended* | 1 `group` bytes, 2 `how` text, 3 `id` bytes, 4 `name` text, 5 `who` bytes |
| *conditions* | 1 `helps` bool, 2 `metered` bool, 3 `plugged_in` bool |
| *conflict* | 1 `copies` [text], 2 `delete_conflict` bool, 3 `path` text, 4 `versions` [*version*] |
| *contact* | 1 `category` text, 2 `connected` bool, 3 `identity` bytes, 4 `introductions` bool, 5 `met` *met*, 6 `name` text, 7 `nearby` bool, 8 `own` bool, 9 `picture` text, 10 `recovered` text, 11 `refused` bool, 12 `relayed` bool, 13 `suggested` text, 14 `trusted` bool, 15 `recovered_seen` uint, 16 `recovered_new_guardians` bool, 17 `recovered_delay` uint, 18 `unreadable` text |
| *contact reach* | 1 `named` [text], 2 `said_no` bool, 3 `shared` bool, 4 `waiting` bool |
| *contact's device* | 1 `addr` text, 2 `bytes_received` uint, 3 `bytes_sent` uint, 4 `carrier` text, 5 `heard_ms_ago` uint, 6 `kept_in_touch` bool, 7 `key` bytes, 8 `online` bool, 9 `open_for_s` uint, 10 `opened_by` text, 11 `packets_dropped` uint, 12 `packets_lost` uint, 13 `route` text, 14 `rtt_ms` uint, 15 `they_see_you_at` text, 16 `through` text, 17 `unreadable` *unreadable*, 18 `kept_alive_s` uint, 19 `path` *known path*, 20 `neighbour` bool |
| *conversation* | 1 `connected` bool, 2 `id` bytes, 3 `introductions` bool, 4 `last` *last message*, 5 `name` text, 6 `nearby` bool, 7 `own` bool, 8 `picture` text, 9 `reach` *contact reach*, 10 `relayed` bool, 11 `suggested` text, 12 `trusted` bool, 13 `unread` uint |
| *copies* | 1 `blobs` uint, 2 `count` uint, 3 `eligible` uint, 4 `holders` [*holder*], 5 `interval_ms` uint, 6 `now` uint, 7 `older_than_ms` uint |
| *data held* | 1 `bytes` uint, 2 `identity` bool, 3 `local` uint, 4 `local_bytes` uint, 5 `objects` uint, 6 `other` bool, 7 `spaces` uint, 8 `unsaved` uint, 9 `unsaved_bytes` uint |
| *deleted file* | 1 `by` text, 2 `folder` bool, 3 `id` bytes, 4 `mine` bool, 5 `name` text, 6 `size` uint, 7 `time` uint |
| *device* | 1 `addr` text, 2 `carrier` text, 3 `fetch` *fetch*, 4 `key` bytes, 5 `name` text, 6 `online` bool, 7 `power` text, 8 `this` bool, 9 `through` text, 10 `unreadable` *unreadable*, 11 `dials` uint, 12 `redial_s` uint |
| *encryption key* | 1 `entry` bytes, 2 `len` uint, 3 `x25519` bytes |
| *endpoint* | 1 `endpoint` text, 2 `local` bool, 3 `tried` bool, 4 `why_not` text |
| *entry* | 1 `accepted` bool, 2 `author` bytes, 3 `author_ok` bool, 4 `bytes` uint, 5 `entry` bytes, 6 `epoch` bytes, 7 `genesis` bool, 8 `open_key` bool, 9 `parents` [bytes], 10 `position` uint, 11 `sealed_id` bytes, 12 `signer` bytes, 13 `starts_epoch` bool, 14 `time` uint, 15 `unwitnessed` bool, 16 `valid` bool, 17 `weigh` *weight*, 18 `wraps` uint |
| *epoch* | 1 `entries` uint, 2 `held` bool, 3 `id` bytes, 4 `started_by` *started by* |
| *fetch* | 1 `latency_ms` uint, 2 `rate` uint, 3 `received` uint, 4 `replies` uint |
| *file* | 1 `added_by` text, 2 `category` bool, 3 `folder` bool, 4 `mine` bool, 5 `name` text, 6 `size` uint, 7 `time` uint, 8 `versions` uint, 9 `who` bytes, 10 `group` bytes |
| *frames* | 1 `in` uint, 2 `new` uint |
| *group* | 1 `admin` bool, 2 `did_not_stand` [bytes], 3 `did_not_stand_changes` [*group change*], 4 `ended` text, 5 `group` bytes, 6 `held_back` uint, 7 `introductions` bool, 8 `last` *last message*, 9 `members` uint, 10 `moved` *group change*, 11 `name` text, 12 `not_posted` uint, 13 `public` bool, 14 `reach` *group reach*, 15 `role` text, 16 `unread` uint, 17 `was` bytes, 18 `confirm` [bytes], 19 `to_confirm` [*group change*] |
| *group change* | 1 `at` uint, 2 `by` text, 3 `group` bytes, 4 `roles` [*role change*], 5 `seen` uint, 6 `taken_out` [text], 7 `device` text, 8 `to` bytes |
| *group reach* | 1 `added` [text], 2 `ask` bool, 3 `public` bool, 4 `said_no` bool, 5 `set` bool, 6 `shared` bool, 7 `waiting` bool, 8 `what` [text], 9 `who` [text], 10 `named` [text] |
| *group shown* | 1 `group` bytes, 2 `name` text, 3 `what` [text] |
| *guarded* | 1 `account_copy` bool, 2 `changes` [*guardian change*], 3 `delay` uint, 4 `delay_text` text, 5 `guardians` uint, 6 `helpers` uint, 7 `id` bytes, 8 `name` text, 9 `never` [text], 10 `persona` bytes, 11 `persona_at` text, 12 `recoveries` [*recovery*], 13 `threshold` uint, 14 `waiting` uint, 15 `warning` text |
| *guardian change* | 1 `caution` text, 2 `confirm_delay` uint, 3 `confirm_delay_text` text, 4 `confirm_from_ms` uint, 5 `confirmed` uint, 6 `confirmed_by_me` bool, 7 `delay` uint, 8 `delay_text` text, 9 `fingerprint` text, 10 `guardians` uint, 11 `id` bytes, 12 `in_effect` bool, 13 `names` [text], 14 `needed` uint, 15 `never` bool, 16 `objected` bool, 17 `threshold` uint, 18 `waits_until_ms` uint |
| *holder* | 1 `checking` bool, 2 `counted` bool, 3 `key` bytes, 4 `last_check` uint, 5 `last_fail` uint, 6 `last_pass` uint, 7 `missed` uint, 8 `name` text, 9 `online` bool, 10 `reason` text, 11 `state` text, 12 `this` bool |
| *host* | 1 `addresses` [text], 2 `key` text (no longer used), 3 `name` text, 4 `key` bytes |
| *hostable* | 1 `name` text, 2 `outside` bool, 3 `sees` text, 4 `services` [text] |
| *hosting* | 1 `accepted` bool, 2 `devices` [text], 3 `ended` bool, 4 `envelopes` uint, 5 `mine` bool, 6 `name` text, 7 `relay_bytes` uint, 8 `sees` text, 9 `waiting` uint, 10 `who` bytes, 11 `serving` [*hostable*], 12 `offered_at` uint, 13 `after` bytes, 14 `accepted_at` uint, 15 `ended_at` uint, 16 `ended_by` bytes, 17 `declined` bool |
| *identity* | 1 `bytes` uint, 2 `contested` bool, 3 `encryption_key` *encryption key*, 4 `encryption_keys_held` uint, 5 `entries` uint, 6 `frozen` bool, 7 `heads` [bytes], 8 `id` bytes, 9 `keys` [*key*], 10 `recovery_policies` uint, 11 `removed` [bytes] |
| *identity entry* | 1 `body` uint, 2 `bytes` uint, 3 `header` *value*, 4 `id` bytes, 5 `in_effect` bool, 6 `ops` [*op*], 7 `parents` [bytes], 8 `signatures` uint, 9 `signer` bytes, 10 `signer_power` text, 11 `valid` bool |
| *inspection* | 1 `on` bool, 2 `until` uint |
| *introduction* | 1 `from` text, 2 `group` text, 3 `id` bytes, 4 `kind` text, 5 `name` text, 6 `note` text |
| *invitation* | 1 `cancelled` bool, 2 `expired` bool, 3 `hosts_only` bool, 4 `id` bytes, 5 `made` uint, 6 `name` text, 7 `outstanding` bool, 8 `used` uint, 9 `uses` uint |
| *kept change* | 1 `at` uint, 2 `by` text, 3 `can_undo` bool, 4 `device` text, 5 `group` bytes, 6 `handed_to` text, 7 `name` text, 8 `roles` [*role change*], 9 `taken_out` [text], 10 `to` bytes, 11 `undo` text, 12 `undone` bytes |
| *key* | 1 `added_in` bytes, 2 `key` bytes, 3 `link_key` *link key*, 4 `name` text, 5 `power` text, 6 `recovery_key` uint, 7 `this_device` bool |
| *kind count* | 1 `bytes` uint, 2 `conflicts` uint, 3 `deleted` uint, 4 `kind` kind, 5 `nodes` uint |
| *known path* | 1 `addr` text, 2 `checking` bool, 3 `confirmed_s_ago` uint, 4 `misses` uint, 5 `next_check_s` uint, 6 `probes` uint, 7 `wait_s` uint |
| *last message* | 1 `from` text, 2 `mine` bool, 3 `text` text, 4 `time` uint |
| *link key* | 1 `len` uint, 2 `x25519` bytes |
| *lost device* | 1 `key` bytes, 2 `name` text, 3 `set_aside` uint |
| *member* | 1 `contact` bool, 2 `id` bytes, 3 `introduce` bool, 4 `left` bool, 5 `name` text, 6 `own` bool, 7 `picture` text, 8 `role` text, 9 `shown` text, 10 `suggested` text, 11 `taken_out` bool, 12 `you` bool, 13 `reach` text, 14 `reaches_you` bool, 15 `through` text |
| *message* | 1 `attachments` [*attachment*], 2 `edited` bool, 3 `from` text, 4 `id` bytes, 5 `mine` bool, 6 `picture` text, 7 `reactions` [*reaction*], 8 `read_by` uint, 9 `reply_to` bytes, 10 `state` text, 11 `text` text, 12 `time` uint |
| *met* | 1 `by` text, 2 `group` text, 3 `how` text, 4 `via` text |
| *nearby* | 1 `they_give_secret` bool, 2 `you_give_secret` bool |
| *network* | 1 `answered` bool, 2 `ask` bool, 3 `known` bool, 4 `mine` bool, 5 `name` text, 6 `router` text, 7 `routers` bool |
| *no longer needed* | 1 `at_ms` uint, 2 `id` bytes, 3 `name` text, 4 `text` text |
| *node* | 1 `bytes` uint, 2 `children` uint, 3 `created` uint, 4 `created_in` bytes, 5 `creator` bytes, 6 `delete_conflict` bool, 7 `deleted` bool, 8 `fields` [[uint]], 9 `id` bytes, 10 `kind` kind, 11 `name` text, 12 `parent` bytes, 13 `position` uint |
| *node field* | 1 `conflict` bool, 2 `k` uint, 3 `values` [*node value*] |
| *node history* | 1 `accepted` bool, 2 `author` bytes, 3 `bytes` uint, 4 `entry` bytes, 5 `index` uint, 6 `op` uint, 7 `time` uint, 8 `valid` bool |
| *node value* | 1 `entry` bytes, 2 `op` uint, 3 `v` *value* |
| *offer* | 1 `from` text, 2 `group` bytes, 3 `members` uint, 4 `name` text, 5 `public` bool, 6 `reach` *group reach* |
| *old versions* | 1 `at` uint, 2 `bytes` uint, 3 `keep` text, 4 `only_here` *only here*, 5 `unchecked` bool |
| *only here* | 1 `bytes` uint, 2 `files` uint |
| *op* | 1 `bytes` uint, 2 `creates` bytes, 3 `index` uint, 4 `kind` kind, 5 `op` *value*, 6 `reach` bool |
| *other log* | 1 `bytes` uint, 2 `entries` uint, 3 `id` bytes, 4 `name` text |
| *pair again* | 1 `key` bytes, 2 `name` text |
| *pairing* | 1 `admin` text, 2 `code` text, 3 `error` text, 4 `state` text, 5 `power` text |
| *peer* | 1 `addr` text, 2 `device` text |
| *place* | 1 `kind` text, 2 `name` text, 3 `who` bytes, 4 `group` bytes |
| *policy* | 1 `history_shared` bool, 2 `public` bool, 3 `rotate_after` uint |
| *progress* | 1 `bytes_fetched` uint, 2 `bytes_pending` uint, 3 `bytes_wanted` uint, 4 `files_pending` uint, 5 `last_error` text, 6 `rate` uint |
| *reach node* | 1 `bytes` uint, 2 `fields` [*node field*], 3 `id` bytes, 4 `identity` bytes |
| *reach seen* | 1 `device` bytes, 2 `endpoints` [*endpoint*], 3 `host` bytes, 4 `session` bool, 5 `this_device` bool |
| *reaction* | 1 `count` uint, 2 `mine` bool, 3 `text` text |
| *recovery* | 1 `caution` text, 2 `confirm_from_ms` uint, 3 `confirmed` uint, 4 `confirmed_by_me` bool, 5 `endorsed` uint, 6 `endorsed_by_me` bool, 7 `fingerprint` text, 8 `id` bytes, 9 `in_effect` bool, 10 `keeps_keys` bool, 11 `objected` bool, 12 `pending` bool |
| *redial* | 1 `alone` bool, 2 `helps` bool, 3 `sparing` *sparing* |
| *rejoin* | 1 `group` bytes, 2 `members` uint, 3 `name` text |
| *relayed for* | 1 `a` text, 2 `a_id` bytes, 3 `b` text, 4 `b_id` bytes |
| *role change* | 1 `from` text, 2 `name` text, 3 `to` text |
| *root* | 1 `children` uint, 2 `id` bytes |
| *router* | 1 `error` text, 2 `everywhere` bool, 3 `external` text, 4 `named` [text], 5 `network` *network*, 6 `on` bool, 7 `protocol` text, 8 `seconds_left` uint, 9 `this_device` bool |
| *set aside* | 1 `entry` bytes, 2 `space` bytes, 3 `time_ms` uint |
| *shape* | 1 `here` bool, 2 `id` bytes, 3 `is` text, 4 `levels` uint, 5 `size` uint |
| *signature* | 1 `key` bytes, 2 `signature` uint (no longer used), 3 `signature` bytes |
| *space* | 1 `entries` uint, 2 `id` bytes, 3 `kind` text, 4 `set_aside` uint, 5 `valid` uint |
| *space held* | 1 `account` bool, 2 `bytes` uint, 3 `entries` uint, 4 `epochs` uint, 5 `files` bool, 6 `id` bytes, 7 `label` text, 8 `members` uint, 9 `my_role` uint, 10 `nodes` uint, 11 `opened` bool, 12 `pending` uint, 13 `profile` kind, 14 `sealed` uint, 15 `successor` bytes, 16 `valid` uint |
| *space member* | 1 `added_by` bytes, 2 `identity` bytes, 3 `left` bool, 4 `log_held` bool, 5 `name` text, 6 `reach_node` bytes, 7 `role` uint |
| *space usage* | 1 `full` bool, 2 `history_bytes` uint, 3 `history_days` uint, 4 `live_bytes` uint, 5 `log_bytes` uint, 6 `name` text, 7 `retention` text, 8 `space` bytes |
| *sparing* | 1 `next_s` uint, 2 `wait_s` uint |
| *started by* | 1 `author` bytes, 2 `entry` bytes, 3 `time` uint |
| *stats* | 1 `appended` uint, 2 `recomputed` uint |
| *step* | 1 `at` uint, 2 `ok` bool, 3 `text` text |
| *store* | 1 `bytes` uint, 2 `objects` uint |
| *stuck item* | 1 `dirty` text, 2 `kind` text, 3 `opens` uint, 4 `path` text, 5 `staged` bool |
| *succession* | 1 `id` text, 2 `space` text |
| *this device* | 1 `key` bytes, 2 `link_x25519` bytes, 3 `name` text |
| *tree item* | 1 `dirty` bool, 2 `ino` uint, 3 `kind` text, 4 `local` bool, 5 `node` bytes, 6 `path` text, 7 `size` uint |
| *unreadable* | 1 `reason` text, 2 `retry_in_s` uint, 3 `says` text, 4 `since` uint, 5 `theirs` bool, 6 `version` text |
| *unshown node* | 1 `name` text, 2 `node` bytes |
| *value* | 1 `cut` bool, 2 `fields` [*value field*], 3 `data` bytes, 4 `inner` *value*, 5 `items` [*value*], 6 `len` uint, 7 `n` uint, 8 `shape` *shape*, 9 `t` text, 10 `v` int or text, 11 `what` text, 12 `withheld` text |
| *value field* | 1 `k` uint, 2 `v` *value* |
| *version* | 1 `current` bool, 2 `device` text, 3 `here` bool, 4 `size` uint, 5 `time` uint, 6 `version` uint, 7 `by` text |
| *voice* | 1 `contact` bool, 2 `identity` bytes, 3 `name` text, 4 `picture` text, 5 `voice` bytes, 6 `you` bool, 7 `camera` bool |
| *weighed op* | 1 `bytes` uint, 2 `kind` kind, 3 `op` kind, 4 `reach` bool |
| *weight* | 1 `aead` uint, 2 `ciphertext` uint, 3 `fields` uint, 4 `header` uint, 5 `ops` [*weighed op*], 6 `sealed` uint, 7 `signature` uint, 8 `wraps` uint |
