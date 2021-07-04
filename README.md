# DJALLIN2

A mildly configurable twitch noisemaker capable of responding to chat and point redemptions.

Available through pip (`djallin2`) or as a [standalone executable](https://github.com/vilhelmen/djallin2/releases) for macOS and Windows.

Note for Windows users, your antivirus will probably think it's a trojan.
It's not, but it kinda looks like one to your antivirus.
If you get the option to report a false positive, please do so.

## Quickstart

Want `!sound` to just work?
* Download the latest build from the [releases tab](https://github.com/vilhelmen/djallin2/releases)
* Download the [quick config file](./quick_config.txt), rename it to `config.txt`
* Place your sounds in a folder called sounds, next to the app and config
* Run it, your browser will open to handle the initial Twitch connection
    * This will happen every ~3 months as necessary

## Configuration

`config.txt` holds your token and configures chat and point responders.

Take a look at the [example configuration](./example_config.txt) for examples, and a detailed explanation for all settings.

The following block defines a basic chat listener:

```toml
[chat.sound]
    badges = ['moderator', 'broadcaster', 'vip']
    target = './sounds/'
    command = '!sound '
```

Mods, VIPs, and the broadcaster can use `!sound xxx` to play `./sounds/xxx.mp3`

If badge and name filters are not supplied, anyone can use the command.
The `random` setting enables random playback.
A value of `2` selects a random file from the directory.
```toml
[chat.wisdom]
    target = './wisdom/'
    command = '!wisdom'
    random = 2
```

Points rewards are similarly configured.
Set the `name` to the name configured in your twitch rewards.
A `random` value of `1` enables the `random` command where a random file will be selected if a user enters `random`.
```toml
[points.sound]
    name = 'play a sound'
    target = './sounds/'
    random = 1
```

Alternatively, you can duplicate configurations using links.
Setting applied in the block with a `link` statement override settings in the linked responder. 
```toml
[points.sound]
    link = 'chat.sound'
    random = 1
```

`command_mode` can be used to define different match modes for the `command`.
`contains` allows you to play a single file or randomly select from a directory when a message contains the command phrase.
Chat listeners are checked in alphabetical order and when one plays a sound, checks stop.
```toml
[chat.z_cowboy]
    command = 'cowboy'
    command_mode = 'contains'
    target = './sound/yeehaw.mp3'
```

Both point and chat blocks support custom code actions, check the [example configuration](./example_config.txt) for details.

Playback statistics can be recorded to a sqlite3 database of your choice.
Simply add `stats = true` to your configuration block.
```toml
[chat.sound]
    target = './sounds/'
    command = '!sound '
    stats = true
```

The name of the database can be changed by setting `stats_db = 'database.sqlite'` at the top of your configuration file.

# Known issues

If a red screen shows when registering your twitch token, there may be a problem with your connection.
Close the soundbot and try again.


# TODO:
1. This
1. Let exit on fire be a configurable option?
1. HTTP command receiver (lioran?)
1. custom hook code - lioran example? obs websocket?
1. Bits?
1. Does linux support audio these days?
1. https://inloop.github.io/sqlite-viewer/
