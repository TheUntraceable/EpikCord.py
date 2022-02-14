from cmath import exp
import threading
from .managers import *
from aiohttp import *
import asyncio
from base64 import b64encode
import datetime
import re
from logging import getLogger
from typing import *
from urllib.parse import quote

CT = TypeVar('CT', bound='Colour')
T = TypeVar('T')
logger = getLogger(__name__)
__version__ = '0.4.9'


"""
Some parts of the code is done by discord.py and their amazing team of contributors
The MIT License (MIT)
Copyright © 2015-2021 Rapptz
Copyright © 2021-present EpikHost
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE."""


_MARKDOWN_ESCAPE_SUBREGEX = '|'.join(
    r'\{0}(?=([\s\S]*((?<!\{0})\{0})))'.format(c) for c in ('*', '`', '_', '~', '|'))

_MARKDOWN_ESCAPE_COMMON = r'^>(?:>>)?\s|\[.+\]\(.+\)'

_MARKDOWN_ESCAPE_REGEX = re.compile(
    fr'(?P<markdown>{_MARKDOWN_ESCAPE_SUBREGEX}|{_MARKDOWN_ESCAPE_COMMON})', re.MULTILINE)

_URL_REGEX = r'(?P<url><[^: >]+:\/[^ >]+>|(?:https?|steam):\/\/[^\s<]+[^<.,:;\"\'\]\s])'

_MARKDOWN_STOCK_REGEX = fr'(?P<markdown>[_\\~|\*`]|{_MARKDOWN_ESCAPE_COMMON})'


def _cancel_tasks(loop) -> None:
    tasks = {t for t in asyncio.all_tasks(loop=loop) if not t.done()}

    if not tasks:
        return

    for task in tasks:
        task.cancel()
    logger.debug(f"Cancelled {len(tasks)} tasks")
    loop.run_until_complete(asyncio.gather(*tasks, return_exceptions=True))


def _cleanup_loop(loop) -> None:
    try:
        _cancel_tasks(loop)
        logger.debug("Shutting down async generators.")
        loop.run_until_complete(loop.shutdown_asyncgens())
    finally:
        loop.close()


class Status:
    def __init__(self, status: str):
        setattr(self, "status", status)


class Activity:
    def __init__(self, *, name: str, type: int, url: Optional[str] = None):
        self.name = name
        self.type = type
        self.url = url

    def to_dict(self):
        return {
            "name": self.name,
            "type": self.type,
            "url": self.url
        }


class UnavailableGuild:
    def __init__(self, data):
        self.data = data
        self.id: str = data.get("id")
        self.available: bool = data.get("available")


class PartialEmoji:
    def __init__(self, data: dict):
        self.data: dict = data
        self.name: str = data.get("name")
        self.id: str = data.get("id")
        self.animated: bool = data.get("animated")

    def to_dict(self):
        payload = {
            "id": self.id,
            "name": self.name,
        }

        if self.animated in (True, False):
            payload["animated"] = self.animated

        return payload


class Reaction:
    def __init__(self, data: dict):
        self.count: int = data.get("count")
        self.me: bool = data.get("me")
        self.emoji: PartialEmoji = PartialEmoji(data.get("emoji"))


class Message:
    def __init__(self, client, data: dict):
        self.client = client
        self.id: str = data.get("id")
        self.channel_id: str = data.get("channel_id")
        self.guild_id: Optional[str] = data.get("guild_id")
        self.webhook_id: Optional[str] = data.get("webhook_id")
        if data.get("author"):
            if self.webhook_id is not None:
                self.author: Optional[Union[WebhookUser, User]] = WebhookUser(
                    data.get("author"))
            else:
                self.author: Optional[Union[WebhookUser, User]] = User(
                    client, data.get("author"))
        else:
            self.author: Optional[Union[WebhookUser, User]] = None
        if data.get("member"):
            self.member: GuildMember = GuildMember(client, data.get("member"))
        # I forgot Message Intents are gonna stop this.
        self.content: Optional[str] = data.get("content")
        self.timestamp: str = data.get("timestamp")
        self.edited_timestamp: Optional[str] = data.get("edited_timestamp")
        self.tts: bool = data.get("tts")
        self.mention_everyone: bool = data.get("mention_everyone")
        self.mentions: Optional[List[MentionedUser]] = [MentionedUser(
            client, mention) for mention in data.get("mentions", [])]
        self.mention_roles: Optional[List[int]] = data.get("mention_roles")
        self.mention_channels: Optional[List[MentionedChannel]] = [
            MentionedChannel(channel) for channel in data.get("mention_channels", [])]
        self.embeds: Optional[List[Embed]] = [
            Embed(**embed) for embed in data.get("embeds", [])]
        self.reactions: Optional[List[Reaction]] = [
            Reaction(reaction) for reaction in data.get("reactions", [])]
        self.nonce: Optional[Union[int, str]] = data.get("nonce")
        self.pinned: bool = data.get("pinned")
        self.type: int = data.get("type")
        self.activity: Optional[MessageActivity] = MessageActivity(
            data.get("activity")) if data.get("activity") else None
        # Despite there being a PartialApplication, Discord don't specify what attributes it has
        self.application: Application = Application(
            data.get("application")) if data.get("application") else None
        self.flags: int = data.get("flags")
        self.referenced_message: Optional[Message] = Message(
            data.get("referenced_message")) if data.get("referenced_message") else None
        self.interaction: Optional[MessageInteraction] = MessageInteraction(
            client, data.get("interaction")) if data.get("interaction") else None
        self.thread: Optional[Thread] = Thread(
            data.get("thread")) if data.get("thread") else None

        components: List[Any] = []
        if data.get("components"):
            for component in data.get("components"):
                if component.get("type") == 1:
                    components.append(MessageActionRow(component))
                elif component.get("type") == 2:
                    components.append(MessageButton(component))
                elif components.get("type") == 3:
                    components.append(MessageSelectMenu(component))
                elif components.get("type") == 4:
                    components.append(MessageTextInputComponent(component))

        self.components: Optional[List[Union[MessageTextInputComponent,
                                             MessageSelectMenu, MessageButton]]] = components
        self.stickers: Optional[List[StickerItem]] = [StickerItem(
            sticker) for sticker in data.get("stickers", [])] or None

    async def add_reaction(self, emoji: str):
        emoji = quote(emoji)
        logger.debug(f"Added a reaction to message ({self.id}).")
        response = await self.client.http.put(f"channels/{self.channel_id}/messages/{self.id}/reactions/{emoji}/@me")
        return await response.json()

    async def remove_reaction(self, emoji: str, user=None):
        emoji = quote(emoji)
        logger.debug(
            f"Removed reaction {emoji} from message ({self.id}) for user {user.username}.")
        if not user:
            response = await self.client.http.delete(f"channels/{self.channel_id}/messages/{self.id}/reactions/{emoji}/@me")
        else:
            response = await self.client.http.delete(f"channels/{self.channel_id}/messages/{self.id}/reactions/{emoji}/{user.id}")
        return await response.json()

    async def fetch_reactions(self, *, after, limit) -> List[Reaction]:
        logger.debug(f"Fetching reactions from message ({self.id}).")
        response = await self.client.http.get(f"channels/{self.channel_id}/messages/{self.id}/reactions?after={after}&limit={limit}")
        return await response.json()

    async def delete_all_reactions(self):
        logger.debug(f"Deleting all reactions from message ({self.id}).")
        response = await self.client.http.delete(f"channels/{self.channel_id}/messages/{self.id}/reactions")
        return await response.json()

    async def delete_reaction_for_emoji(self, emoji: str):
        logger.debug(
            f"Deleting a reaction from message ({self.id}) for emoji {emoji}.")
        emoji = quote(emoji)
        response = await self.client.http.delete(f"channels/{self.channel_id}/messages/{self.id}/reactions/{emoji}")
        return await response.json()

    async def edit(self, message_data: dict):
        logger.debug(
            f"Editing message {self.id} with message_data {message_data}.")
        response = await self.client.http.patch(f"channels/{self.channel_id}/messages/{self.id}", data=message_data)
        return await response.json()

    async def delete(self):
        logger.debug(f"Deleting message {self.id}.")
        response = await self.client.http.delete(f"channels/{self.channel_id}/messages/{self.id}")
        return await response.json()

    async def pin(self, *, reason: Optional[str]):
        headers = self.client.http.headers.copy()
        if reason:
            headers["X-Audit-Log-Reason"] = reason
            logger.debug(f"Pinning message {self.id} with reason {reason}.")
        else:
            logger.debug(f"Pinning message {self.id}.")
        response = await self.client.http.put(f"channels/{self.channel_id}/pins/{self.id}", headers=headers)
        return await response.json()

    async def unpin(self, *, reason: Optional[str]):
        headers = self.client.http.headers.copy()
        if reason:
            headers["X-Audit-Log-Reason"] = reason
            logger.debug(f"Unpinning message {self.id} with reason {reason}.")
        else:
            logger.debug(f"Unpinning message {self.id}.")
        response = await self.client.http.delete(f"channels/{self.channel_id}/pins/{self.id}", headers=headers)
        return await response.json()

    async def start_thread(self, name: str, auto_archive_duration: Optional[int], rate_limit_per_user: Optional[int]):
        logger.debug(
            f"Starting thread for message {self.id} with name {name}, auto archive duration {auto_archive_duration or None}, ratelimit per user {rate_limit_per_user or None}.")
        response = await self.client.http.post(f"channels/{self.channel_id}/messages/{self.id}/threads", data={"name": name, "auto_archive_duration": auto_archive_duration, "rate_limit_per_user": rate_limit_per_user})
        # Cache it
        self.client.guilds[self.guild_id].append(Thread(await response.json()))
        return Thread(await response.json())

    async def crosspost(self):
        logger.debug(f"Crossposting message {self.id}.")
        response = await self.client.http.post(f"channels/{self.channel_id}/messages/{self.id}/crosspost")
        return await response.json()


class Messageable:
    def __init__(self, client, channel_id: str):
        self.id: str = channel_id
        self.client = client

    async def fetch_messages(self, *, around: Optional[str] = None, before: Optional[str] = None, after: Optional[str] = None, limit: Optional[int] = None) -> List[Message]:
        response = await self.client.http.get(f"channels/{self.id}/messages", params={"around": around, "before": before, "after": after, "limit": limit})
        data = await response.json()
        return [Message(message) for message in data]

    async def fetch_message(self, *, message_id: str) -> Message:
        response = await self.client.http.get(f"channels/{self.id}/messages/{message_id}")
        data = await response.json()
        return Message(data)

    async def send(self, content: Optional[str] = None, *, embeds: Optional[List[dict]] = None, components=None, tts: Optional[bool] = False, allowed_mentions=None, sticker_ids: Optional[List[str]] = None, attachments=None, suppress_embeds: bool = False) -> Message:
        payload = {}

        if content:
            payload["content"] = content

        if embeds:
            payload["embeds"] = [embed.to_dict() for embed in embeds]

        if components:
            payload["components"] = [component.to_dict()
                                     for component in components]

        if tts:
            payload["tts"] = tts

        if allowed_mentions:
            payload["allowed_mentions"] = allowed_mentions.to_dict()

        if sticker_ids:
            payload["sticker_ids"] = sticker_ids

        if attachments:
            payload["attachments"] = [attachment.to_dict()
                                      for attachment in attachments]

        if suppress_embeds:
            payload["suppress_embeds"] = 1 << 2

        response = await self.client.http.post(f"channels/{self.id}/messages", json=payload)
        print(response.status)
        print(payload)
        data = await response.json()
        return Message(self.client, data)


class User(Messageable):
    def __init__(self, client, data: dict):
        super().__init__(client, data["id"])
        self.data = data
        self.client = client
        self.id: str = data.get("id")
        self.username: str = data.get("username")
        self.discriminator: str = data.get("discriminator")
        self.avatar: Optional[str] = data.get("avatar")
        self.bot: Optional[bool] = data.get("bot")
        self.system: Optional[bool] = data.get("system")
        self.mfa_enabled: bool = data.get("mfa_enabled")
        self.banner: Optional[str] = data.get("banner")
        # the user's banner color encoded as an integer representation of hexadecimal color code
        self.accent_color: Optional[int] = data.get("accent_color")
        self.locale: Optional[str] = data.get("locale")
        self.verified: bool = data.get("verified")
        self.email: Optional[str] = data.get("email")
        self.flags: int = data.get("flags")
        self.premium_type: int = data.get("premium_type")
        self.public_flags: int = data.get("public_flags")


class EventHandler:
    # Class that'll contain all methods that'll be called when an event is triggered.

    def __init__(self):
        self.events = {}

    async def handle_events(self):
        async for event in self.ws:
            event = event.json()

            if event["op"] == self.HELLO:

                self.interval = event["d"]["heartbeat_interval"]

                await self.identify()

            elif event["op"] == self.EVENT:
                await self.handle_event(event["t"], event["d"])

            elif event["op"] == self.HEARTBEAT:
                # I shouldn't wait the remaining delay according to the docs.
                await self.heartbeat(True)

            elif event["op"] == self.HEARTBEAT_ACK:
                try:
                    self.heartbeats.append(event["d"])
                except AttributeError:
                    self.heartbeats = [event["d"]]
                self.sequence = event["s"]
            logger.debug(f"Received event {event['t']}")
        await self.handle_close()

    async def handle_event(self, event_name: str, data: dict):
        event_name = event_name.lower()
        # try:
        await getattr(self, event_name)(data)
        # except AttributeError:
        #     logger.warning(f"A new event, {event_name}, has been added and EpikCord hasn't added that yet. Open an issue to be the first!")

    async def channel_create(self, data: dict):

        channel_data: dict = data.get("d")
        channel_type: str = channel_data.get("type")
        event_func = None
        try:
            event_func = self.events["channel_create"]
        except KeyError:
            ...
        
        if channel_type in (0, 1, 5, 6, 10, 11, 12):
            
            if event_func:
                await event_func(TextBasedChannel(self.http, channel_data))

        elif channel_type == 2:
            if event_func:
                await event_func(VoiceChannel(self.http, channel_data))
        
        elif channel_type == 13:
            if event_func:
                await event_func(GuildStageChannel(self.http, channel_data))

        # if channel_type in (0, 5, 6):
        #     try:
        #         event_func = self.events["channel_create"]
        #     except KeyError:
        #         ...
        #     if event_func:
        #         await event_func(TextBasedChannel(self, channel_data))

        # elif channel_type == 1:
        #     try:
        #         event_func = self.events["dm_channel_create"]
        #         await event_func(DMChannel(self, channel_data))
        #     except KeyError:
        #         pass
        
        # elif channel_type == 2:
        #     try:
        #         event_func = self.events["channel_create"]
        #     except KeyError:
        #         pass    
        #     await event_func(VoiceChannel(self, channel_data))
        
        # elif channel_type == 13:
        #     try:
        #         event_func = self.events["channel_create"]
        #     except KeyError:
        #         pass
        #     await event_func(GuildStageChannel(self, channel_data))
        
        # elif channel_type in (10, 11, 12)


    async def message_create(self, data: dict):
        await self.events["message_create"](Message(self, data))

    def event(self, func):
        self.events[func.__name__.lower().replace("on_", "")] = func

    async def ready(self, data: dict):
        self.user: ClientUser = ClientUser(self.session, data.get("user"))
        application_response = await self.session.get("https://discord.com/api/v9/oauth2/applications/@me", headers={"Authorization": f"Bot {self.token}"})
        application_data = await application_response.json()
        self.application: ClientApplication = ClientApplication(
            self.session, application_data)

        def heartbeater():
            loop = asyncio.new_event_loop()
            loop.run_until_complete(self.heartbeat(False))
            loop.run_forever()

        threading._start_new_thread(heartbeater, ())
        try:
            await self.events["ready"]()
        except KeyError:
            return


class WebsocketClient(EventHandler):
    def __init__(self, token: str, intents: int):

        super().__init__()

        self.EVENT = 0
        self.HEARTBEAT = 1
        self.IDENTIFY = 2
        self.PRESENCE_UPDATE = 3
        self.VOICE_STATE_UPDATE = 4
        self.RESUME = 6
        self.RECONNECT = 7
        self.REQUEST_GUILD_MEMBERS = 8
        self.INVALID_SESSION = 9
        self.HELLO = 10
        self.HEARTBEAT_ACK = 11

        self.token = token

        if isinstance(intents, int):
            self.intents = intents
        elif isinstance(intents, Intents):
            self.intents = intents.value

        self.session = ClientSession()
        self.commands = {}
        self._closed = False  # Well nah we're starting closed
        self.heartbeats = []
        self.average_latency = 0

        self.interval = None  # How frequently to heartbeat
        self.session_id = None
        self.sequence = None

    async def heartbeat(self, forced: Optional[bool] = None):
        if forced:
            return await self.send_json({"op": self.HEARTBEAT, "d": self.sequence or "null"})

        if self.interval:
            while True:
                await asyncio.sleep(self.interval / 1000)
                await self.send_json({"op": self.HEARTBEAT, "d": self.sequence or "null"})
                print("Sent a heartbeat!")

    async def handle_close(self):
        if self.ws.close_code == 4014:
            raise DisallowedIntents(
                "You cannot use privellaged intents with this token, go to the developer portal and allow the privellaged intents needed.")
        elif self.ws.close_code == 4004:
            raise InvalidToken("The token you provided is invalid.")
        elif self.ws.close_code == 4008:
            raise Ratelimited429(
                "You've been rate limited. Try again in a few minutes.")
        elif self.ws.close_code == 4013:
            raise InvalidIntents("The intents you provided are invalid.")
        else:
            print(self.ws.close_code)

    async def send_json(self, json: dict):
        try:
            await self.ws.send_json(json)
        except:
            logger.debug(f"Exited with code: {self.ws.close_code}")

    async def connect(self):
        self.ws = await self.session.ws_connect("wss://gateway.discord.gg/?v=9&encoding=json")
        await self.handle_events()
        self._closed = False

    async def resume(self):
        await self.send_json({
            'op': self.RESUME,
            'd': {
                'seq': self.sequence,
                'session_id': self.session_id,
                'token': self.token
            }
        })
        self._closed = False

    async def identify(self):
        await self.send_json({
            "op": self.IDENTIFY,
            "d": {
                "token": self.token,
                "intents": self.intents,
                "properties": {
                    "$os": "linux",
                    "$browser": "EpikCord.py",
                    "$device": "EpikCord.py"
                }
            }
        }
        )

    async def close(self) -> None:
        if self._closed:
            return

        self._closed = True

        # for voice in self.voice_clients:
        #     try:
        #         await voice.disconnect(force=True)
        #     except Exception:
        #         # if an error happens during disconnects, disregard it.
        #         pass

        if self.ws is not None:
            if not self.ws.closed:
                await self.ws.close(code=1000)

        if self.http is not None:
            if not self.http.closed:
                await self.http.close()

        self._closed = True

    def login(self):

        loop = asyncio.get_event_loop()

        async def runner():
            try:
                await self.connect()
            finally:
                if self._closed != True:
                    await self.close()

        def stop_loop_on_completion(f: asyncio.Future):
            loop.stop()

        future = asyncio.ensure_future(runner(), loop=loop)
        future.add_done_callback(stop_loop_on_completion)

        try:
            loop.run_forever()
        except KeyboardInterrupt:
            pass
        finally:
            future.remove_done_callback(stop_loop_on_completion)
            _cleanup_loop(loop)

class VoiceWebsocketClient:
    def __init__(self):
        self.ws = None

class BaseSlashCommandOption:
    def __init__(self, *, name: str, description: str, required: bool = False):
        self.settings = {
            "name": name,
            "description": description,
            "required": required
        }
        # People shouldn't use this class, this is just a base class for other options


class Subcommand(BaseSlashCommandOption):
    def __init__(self, *, name: str, description: Optional[str] = None, required: bool = False):
        super().__init__(name=name, description=description, required=required)
        self.settings["type"] = 1


class SubCommandGroup(BaseSlashCommandOption):
    def __init__(self, *, name: str, description: Optional[str] = None, required: bool = False):
        super().__init__(name=name, description=description, required=required)
        self.settings["type"] = 2


class StringOption(BaseSlashCommandOption):
    def __init__(self, *, name: str, description: Optional[str] = None, required: bool = False):
        super().__init__(name=name, description=description, required=required)
        self.settings["type"] = 3


class IntegerOption(BaseSlashCommandOption):
    def __init__(self, *, name: str, description: Optional[str] = None, required: bool = False):
        super().__init__(name=name, description=description, required=required)
        self.settings["type"] = 4


class BooleanOption(BaseSlashCommandOption):
    def __init__(self, *, name: str, description: Optional[str] = None, required: bool = False):
        super().__init__(name=name, description=description, required=required)
        self.settings["type"] = 5


class UserOption(BaseSlashCommandOption):
    def __init__(self, *, name: str, description: Optional[str] = None, required: bool = False):
        super().__init__(name=name, description=description, required=required)
        self.settings["type"] = 6


class ChannelOption(BaseSlashCommandOption):
    def __init__(self, *, name: str, description: Optional[str] = None, required: bool = False):
        super().__init__(name=name, description=description, required=required)
        self.settings["type"] = 7


class RoleOption(BaseSlashCommandOption):
    def __init__(self, *, name: str, description: Optional[str] = None, required: bool = False):
        super().__init__(name=name, description=description, required=required)
        self.settings["type"] = 8


class MentionableOption(BaseSlashCommandOption):
    def __init__(self, *, name: str, description: Optional[str] = None, required: bool = False):
        super().__init__(name=name, description=description, required=required)
        self.settings["type"] = 9


class NumberOption(BaseSlashCommandOption):
    def __init__(self, *, name: str, description: Optional[str] = None, required: bool = False):
        super().__init__(name=name, description=description, required=required)
        self.settings["type"] = 10


class AttachmentOption(BaseSlashCommandOption):
    def __init__(self, *, name: str, description: Optional[str] = None, required: bool = False):
        super().__init__(name=name, description=description, required=required)
        self.settings["type"] = 11


class SlashCommandOptionChoice:
    def __init__(self, * name: str, value: Union[float, int, str]):
        self.settings = {
            "name": name,
            "value": value
        }


class Overwrite:
    def __init__(self, data: dict):
        self.id: str = data.get("id")
        self.type: int = data.get("type")
        self.allow: str = data.get("allow")
        self.deny: str = data.get("deny")


class StickerItem:
    def __init__(self, data: dict):
        self.id: str = data.get("id")
        self.name: str = data.get("name")
        self.description: str = data.get("description")
        self.tags: str = data.get("tags")
        self.type: str = data.get("image")
        self.format_type: int = data.get("format_type")
        self.pack_id: int = data.get("pack_id")
        self.sort_value: int = data.get("sort_value")


class ThreadMember:
    def __init__(self, data: dict):
        self.id: str = data.get("user_id")
        self.thread_id: str = data.get("thread_id")
        self.join_timestamp: str = data.get("join_timestamp")
        self.flags: int = data.get("flags")


class Thread:
    def __init__(self, client, data: dict):
        super().__init__(client, data)
        self.owner_id: str = data.get("owner_id")
        self.message_count: int = data.get("message_count")
        self.member_count: int = data.get("member_count")
        self.archived: bool = data.get("archived")
        self.auto_archive_duration: int = data.get("auto_archive_duration")
        self.archive_timestamp: str = data.get("archive_timestamp")
        self.locked: bool = data.get("locked")

    async def join(self):
        if self.archived:
            raise ThreadArchived(
                "This thread has been archived so it is no longer joinable")
        response = await self.client.http.put(f"/channels/{self.id}/thread-members/@me")
        return await response.json()

    async def add_member(self, member_id: str):
        if self.archived:
            raise ThreadArchived(
                "This thread has been archived so it is no longer joinable")

        response = await self.client.http.put(f"/channels/{self.id}/thread-members/{member_id}")
        return await response.json()

    async def leave(self):
        if self.archived:
            raise ThreadArchived(
                "This thread has been archived so it is no longer leaveable")
        response = await self.client.http.delete(f"/channels/{self.id}/thread-members/@me")
        return await response.json()

    async def remove_member(self, member_id: str):
        if self.archived:
            raise ThreadArchived(
                "This thread has been archived so it is no longer leaveable")

        response = await self.client.http.delete(f"/channels/{self.id}/thread-members/{member_id}")
        return await response.json()

    async def fetch_member(self, member_id: str) -> ThreadMember:
        response = await self.client.http.get(f"/channels/{self.id}/thread-members/{member_id}")
        if response.status == 404:
            raise NotFound404(
                "The member you are trying to fetch does not exist")
        return ThreadMember(await response.json())

    async def list_members(self) -> List[ThreadMember]:
        response = await self.client.http.get(f"/channels/{self.id}/thread-members")
        return [ThreadMember(member) for member in await response.json()]

    async def bulk_delete(self, message_ids: List[str], reason: Optional[str]) -> None:

        if reason:
            headers = self.client.http.headers.copy()
            headers["X-Audit-Log-Reason"] = reason

        response = await self.client.http.post(f"channels/{self.id}/messages/bulk-delete", data={"messages": message_ids}, headers=headers)
        return await response.json()


def _get_mime_type_for_image(data: bytes):
    if data.startswith(b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A'):
        return 'image/png'
    elif data[0:3] == b'\xff\xd8\xff' or data[6:10] in (b'JFIF', b'Exif'):
        return 'image/jpeg'
    elif data.startswith((b'\x47\x49\x46\x38\x37\x61', b'\x47\x49\x46\x38\x39\x61')):
        return 'image/gif'
    elif data.startswith(b'RIFF') and data[8:12] == b'WEBP':
        return 'image/webp'
    else:
        raise InvalidArgumentType('Unsupported image type given')


def _bytes_to_base64_data(data: bytes) -> str:
    fmt = 'data:{mime};base64,{data}'
    mime = _get_mime_type_for_image(data)
    b64 = b64encode(data).decode('ascii')
    return fmt.format(mime=mime, data=b64)


class BaseChannel:
    def __init__(self, client, data: dict):
        self.id: str = data.get("id")
        self.client = client
        self.type = data.get("type")


class BaseComponent:
    def __init__(self, *, custom_id: str):
        self.custom_id: str = custom_id

    def set_custom_id(self, custom_id: str):

        if not isinstance(custom_id, str):
            raise InvalidArgumentType("Custom Id must be a string.")

        elif len(custom_id) > 100:
            raise CustomIdIsTooBig("Custom Id must be 100 characters or less.")

        self.settings["custom_id"] = custom_id


class Application:
    def __init__(self, data: dict):
        self.id: str = data.get("id")
        self.name: str = data.get("name")
        self.icon: Optional[str] = data.get("icon")
        self.description: str = data.get("description")
        self.rpc_origins: Optional[list] = data.get("rpc_origins")
        self.bot_public: bool = data.get("bot_public")
        self.bot_require_code_grant: bool = data.get("bot_require_code_grant")
        self.terms_of_service_url: Optional[str] = data.get("terms_of_service")
        self.privacy_policy_url: Optional[str] = data.get("privacy_policy")
        self.owner: Optional[PartialUser] = PartialUser(
            data.get("user")) if data.get("user") else None
        self.summary: str = data.get("summary")
        self.verify_key: str = data.get("verify_key")
        self.team: Optional[Team] = Team(
            data.get("team")) if data.get("get") else None
        self.cover_image: Optional[str] = data.get("cover_image")
        self.flags: int = data.get("flags")


class ClientApplication(Application):
    def __init__(self, client, data: dict):
        super().__init__(data)
        self.client = client

    async def fetch(self):
        response: ClientResponse = await self.client.http.get("oauth2/applications/@me")
        data: dict = await response.json()
        return Application(data)


class ApplicationCommand:
    def __init__(self, data: dict):
        self.id: str = data.get("id")
        self.type: int = data.get("type")
        self.application_id: str = data.get("application_id")
        self.guild_id: Optional[str] = data.get("guild_id")
        self.name: str = data.get("name")
        self.description: str = data.get("description")
        self.default_permissions: bool = data.get("default_permissions")
        self.version: str = data.get("version")


class Attachment:
    def __init__(self, data: dict):
        self.id: str = data.get("id")
        self.file_name: str = data.get("filename")
        self.description: Optional[str] = data.get("description")
        self.content_type: Optional[str] = data.get("content_type")
        self.size: int = data.get("size")
        self.proxy_url: str = data.get("proxy_url")
        self.width: Optional[int] = data.get("width")
        self.height: Optional[int] = data.get("height")
        self.ephemeral: Optional[bool] = data.get("ephemeral")


class GuildChannel(BaseChannel):
    def __init__(self, client, data: dict):
        super().__init__(client, data)
        if data["type"] == 0:
            return TextBasedChannel(client, data)
        self.guild_id: str = data.get("guild_id")
        self.position: int = data.get("position")
        self.nsfw: bool = data.get("nsfw")
        self.permission_overwrites: List[dict] = data.get(
            "permission_overwrites")
        self.parent_id: str = data.get("parent_id")
        self.name: str = data.get("name")

    async def delete(self, *, reason: Optional[str] = None) -> None:
        if reason:
            headers = self.client.http.headers.copy()
            if reason:
                headers["reason"] = reason

        response = await self.client.http.delete(f"/channels/{self.id}", headers=headers)
        return await response.json()

    async def fetch_invites(self):
        response = await self.client.http.get(f"/channels/{self.id}/invites")
        return await response.json()

    async def create_invite(self, *, max_age: Optional[int], max_uses: Optional[int], temporary: Optional[bool], unique: Optional[bool], target_type: Optional[int], target_user_id: Optional[str], target_application_id: Optional[str]):
        data = {}
        data["max_age"] = max_age or None
        data["max_uses"] = max_uses or None
        data["temporary"] = temporary or None
        data["unique"] = unique or None
        data["target_type"] = target_type or None
        data["target_user_id"] = target_user_id or None
        data["target_application_id"] = target_application_id or None
        await self.client.http.post(f"/channels/{self.id}/invites", json=data)

    async def delete_overwrite(self, overwrites: Overwrite) -> None:
        response = await self.client.http.delete(f"/channels/{self.id}/permissions/{overwrites.id}")
        return await response.json()

    async def fetch_pinned_messages(self) -> List[Message]:
        response = await self.client.http.get(f"/channels/{self.id}/pins")
        data = await response.json()
        return [Message(message) for message in data]

    # async def edit_permission_overwrites I'll do this later

    # async def edit(self, *,name: str, position: str, permission_overwrites: List[dict], reason: Optional[str] = None):
    #     data = {}
    #     if name:
    #         data["name"] = name
    #     if position:
    #         data["position"] = position
    #     if permission_overwrites:
    #         data["permission_overwrites"] = permission_overwrites
    #     headers = self.client.http.headers
    #     headers["X-Audit-Log-Reason"] = reason
    #     response = await self.client.http.patch(f"channels/{self.id}", data=data, headers=headers)
    #     data = await response.json()
    #     return GuildChannel(self.client, data)


class GuildTextChannel(GuildChannel, Messageable):
    def __init__(self, client, data: dict):
        super().__init__(client, data)
        self.topic: str = data.get("topic")
        self.rate_limit_per_user: int = data.get("rate_limit_per_user")
        self.last_message_id: str = data.get("last_message_id")
        self.default_auto_archive_duration: int = data.get(
            "default_auto_archive_duration")

    async def create_webhook(self, *, name: str, avatar: Optional[str] = None, reason: Optional[str] = None):
        headers = client.http.headers.clone()
        if reason:
            headers["X-Audit-Log-Reason"] = reason

    async def start_thread(self, name: str, *, auto_archive_duration: Optional[int], type: Optional[int], invitable: Optional[bool], rate_limit_per_user: Optional[int], reason: Optional[str]):
        data = {"name": name}
        if auto_archive_duration:
            data["auto_archive_duration"] = auto_archive_duration
        if type:
            data["type"] = type
        if invitable is not None:  # Geez having a bool is gonna be a pain
            data["invitable"] = invitable
        if rate_limit_per_user:
            data["rate_limit_per_user"] = rate_limit_per_user

        headers = self.client.http.headers.copy()
        headers["X-Audit-Log-Reason"] = reason

        response = await self.client.http.post(f"/channels/{self.id}/threads", data=data, headers=headers)
        self.client.guilds[self.guild_id].append(Thread(await response.json()))

    async def bulk_delete(self, message_ids: List[str], reason: Optional[str]) -> None:

        if reason:
            headers = self.client.http.headers.copy()
            headers["X-Audit-Log-Reason"] = reason

        response = await self.client.http.post(f"channels/{self.id}/messages/bulk-delete", data={"messages": message_ids}, headers=headers)
        return await response.json()

    # It returns a List of Threads but I can't typehint that...
    async def list_public_archived_threads(self, *, before: Optional[str], limit: Optional[int]) -> Dict[str, Union[List[Messageable], List[ThreadMember], bool]]:
        response = await self.client.http.get(f"/channels/{self.id}/threads/archived/public", params={"before": before, "limit": limit})
        return await response.json()

    # It returns a List of Threads but I can't typehint that...
    async def list_private_archived_threads(self, *, before: Optional[str], limit: Optional[int]) -> Dict[str, Union[List[Messageable], List[ThreadMember], bool]]:
        response = await self.client.http.get(f"/channels/{self.id}/threads/archived/private", params={"before": before, "limit": limit})
        return await response.json()

    async def list_joined_private_archived_threads(self, *, before: Optional[str], limit: Optional[int]) -> Dict[str, Union[List[Messageable], List[ThreadMember], bool]]:
        response = await self.client.http.get(f"/channels/{self.id}/threads/archived/private", params={"before": before, "limit": limit})
        return await response.json()

    # async def edit(self,*, name: Optional[str], position: Optional[str], permission_overwrites: Optional[List[dict]], reason: Optional[str], topic: Optional[str], nsfw: bool, rate_limit_per_user: Optional[int], parent_id: Optional[int], default_auto_archive_duration: Optional[int]):
    #     data = {}
    #     if name:
    #         data["name"] = name
    #     if position:
    #         data["position"] = position
    #     if permission_overwrites:
    #         data["permission_overwrites"] = permission_overwrites

    #     headers = self.client.http.headers
    #     headers["X-Audit-Log-Reason"] = reason
    #     response = await self.client.http.patch(f"channels/{self.id}", data=data, headers=headers)
    #     data = await response.json()
    #     return GuildTextChannel(self.client, data)


class GuildNewsChannel(GuildTextChannel):
    def __init__(self, client, data: dict):
        super().__init__(client, data)
        self.default_auto_archive_duration: int = data.get(
            "default_auto_archive_duration")

    async def follow(self, webhook_channel_id: str):
        response = await self.client.http.post(f"/channels/{self.id}/followers", data={"webhook_channel_id": webhook_channel_id})
        return await response.json()


class VoiceChannel(GuildChannel):
    def __init__(self, client, data: dict):
        super().__init__(client, data)
        self.bitrate: int = data.get("bitrate")
        self.user_limit: int = data.get("user_limit")
        self.rtc_region: str = data.get("rtc_region")


class DMChannel(BaseChannel):
    def __init__(self, client, data: dict):
        super().__init__(client, data)
        self.recipient: List[PartialUser] = PartialUser(data.get("recipient"))


class ChannelCategory(GuildChannel):
    def __init__(self, client, data: dict):
        super().__init__(client, data)


class GuildStoreChannel(GuildChannel):
    def __init__(self, client, data: dict):
        super().__init__(client, data)


class GuildNewsThread(Thread, GuildNewsChannel):
    def __init__(self, client, data: dict):
        super().__init__(client, data)


class GuildStageChannel(BaseChannel):
    def __init__(self, client, data: dict):
        super().__init__(client, data)
        self.guild_id: str = data.get("guild_id")
        self.channel_id: str = data.get("channel_id")
        self.privacy_level: int = data.get("privacy_level")
        self.discoverable_disabled: bool = data.get("discoverable_disabled")


class TextBasedChannel(BaseChannel):
    def __init__(self, client, data: dict):
        super().__init__(data)
        if self.type == 0:
            return GuildTextChannel(client, data)

        elif self.type == 1:
            return DMChannel(data)

        elif self.type == 4:
            return ChannelCategory(client, data)

        elif self.type == 5:
            return GuildNewsChannel(client, data)

        elif self.type == 6:
            return GuildStoreChannel(client, data)

        elif self.type == 10:
            return GuildNewsThread(client, data)

        elif self.type == 11 or self.type == 12:
            return Thread(client, data)

        elif self.type == 13:
            return GuildStageChannel(client, data)


class HTTPClient(ClientSession):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.base_uri: str = "https://discord.com/api/v9"

    async def get(self, url, *args, **kwargs):
        if url.startswith("/"):
            url = url[1:]
        return await super().get(f"{self.base_uri}/{url}", *args, **kwargs)

    async def post(self, url, *args, **kwargs):
        if url.startswith("/"):
            url = url[1]
        return await super().post(f"{self.base_uri}/{url}", *args, **kwargs)

    async def patch(self, url, *args, **kwargs):
        if url.startswith("/"):
            url = url[1:]
        return await super().patch(f"{self.base_uri}/{url}", *args, **kwargs)

    async def delete(self, url, *args, **kwargs):
        if url.startswith("/"):
            url = url[1:]
        return await super().delete(f"{self.base_uri}/{url}", *args, **kwargs)

    async def put(self, url, *args, **kwargs):
        if url.startswith("/"):
            url = url[1:]
        return await super().put(f"{self.base_uri}/{url}", *args, **kwargs)

    async def head(self, url, *args, **kwargs):
        if url.startswith("/"):
            url = url[1:]
        return await super().head(f"{self.base_uri}/{url}", *args, **kwargs)


class Section:
    def __init__(self):
        self.commands = {}
        self.events = {}

    def event(self, event_name: str):
        def register_event(func):
            self.events[event_name] = func
        return register_event

    def slash_command(self, *, name: str, description: Optional[str], options: List[Union[Subcommand, SubCommandGroup, StringOption, IntegerOption, BooleanOption, UserOption, ChannelOption, RoleOption, MentionableOption, NumberOption]]):
        def register_slash_command(func):
            self.commands[name] = {
                "callback": func,
                "name": name,
                "description": description,
                "options": options
            }
        return register_slash_command

class MissingDescription(Exception):
    ...

class Client(WebsocketClient):

    def __init__(self, token: str, intents: int = 0, **options):
        super().__init__(token, intents)

        self.commands: List[ApplicationCommand] = []

        self.options: dict = options

        self.http = HTTPClient(
            headers={
                "Authorization": f"Bot {token}",
                "User-Agent": f"DiscordBot (https://github.com/EpikCord/EpikCord.py {__version__})"
            }
        )

        self.user: ClientUser = None
        self.application: Application = None

    def command(self, *,
                name: str,
                description: str,
                guild_ids: Optional[List[str]],
                options: Optional[
            Union[
                Subcommand,
                SubCommandGroup,
                StringOption,
                IntegerOption,
                BooleanOption,
                UserOption,
                ChannelOption,
                RoleOption,
                MentionableOption,
                NumberOption,
                AttachmentOption
            ]]
    ):
        def register_slash_command(func):
            if not description:
                raise MissingDescription(f"You must supply a description for the command {name}.")
            self.commands[func.__name__] = SlashCommand({
                "callback": func,
                "name": name,
                "description": description,
                "guild_ids": guild_ids,
                "options": options
            })
        return register_slash_command

    def add_section(self, section: Section):
        if not isinstance(section, Section):
            raise InvalidArgumentType(
                "You must pass in a class that inherits from the Section class.")
        for name, command_object in section.commands:
            self.commands[name] = command_object

        for event_name, event_func in section.events:
            self.events[event_name.lower().replace("on_")] = event_func

        # Successfully extracted all the valuable stuff from the section
# class ClientGuildMember(Member):
#     def __init__(self, client: Client,data: dict):
#         super().__init__(data)


class Colour:
    # Some of this code is sourced from discord.py, rest assured all the colors are different from discord.py
    __slots__ = ('value',)

    def __init__(self, value: int):
        if not isinstance(value, int):
            raise TypeError(
                f'Expected int parameter, received {value.__class__.__name__} instead.')

        self.value: int = value

    def _get_byte(self, byte: int) -> int:
        return (self.value >> (8 * byte)) & 0xff

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, Colour) and self.value == other.value

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def __str__(self) -> str:
        return f'#{self.value:0>6x}'

    def __int__(self) -> int:
        return self.value

    def __repr__(self) -> str:
        return f'<Colour value={self.value}>'

    def __hash__(self) -> int:
        return hash(self.value)

    @property
    def r(self) -> int:
        """Return the red component in rgb"""
        return self._get_byte(2)

    @property
    def g(self) -> int:
        """Return the green component in rgb"""
        return self._get_byte(1)

    @property
    def b(self) -> int:
        """Return the blue component in rgb"""
        return self._get_byte(0)

    def to_rgb(self) -> Tuple[int, int, int]:
        """Returns an rgb color as a tuple"""
        return (self.r, self.g, self.b)

    @classmethod
    def from_rgb(cls: Type[CT], r: int, g: int, b: int) -> CT:
        """Constructs a :class:`Colour` from an RGB tuple."""
        return cls((r << 16) + (g << 8) + b)

    @classmethod
    def lime_green(cls: Type[CT]) -> CT:
        """Returns a color of lime green"""
        return cls(0x00ff01)

    @classmethod
    def light_green(cls: Type[CT]) -> CT:
        """Returns a color of light green"""
        return cls(0x00ff22)

    @classmethod
    def dark_green(cls: Type[CT]) -> CT:
        """Returns a color of dark green"""
        return cls(0x00570a)

    @classmethod
    def light_blue(cls: Type[CT]) -> CT:
        """Returns a color of light blue"""
        return cls(0x00ff01)

    @classmethod
    def dark_blue(cls: Type[CT]) -> CT:
        """Returns a color of dark blue"""
        return cls(0x0a134b)

    @classmethod
    def light_red(cls: Type[CT]) -> CT:
        """Returns a color of light red"""
        return cls(0xaa5b54)

    @classmethod
    def dark_red(cls: Type[CT]) -> CT:
        """Returns a color of dark red"""
        return cls(0x4c0000)

    @classmethod
    def black(cls: Type[CT]) -> CT:
        """Returns a color of black"""
        return cls(0x000000)

    @classmethod
    def white(cls: Type[CT]) -> CT:
        """Returns a color of white"""
        return cls(0xffffff)

    @classmethod
    def lightmode(cls: Type[CT]) -> CT:
        """Returns the color of the background when the color theme in Discord is set to light mode. An alias of `white`"""
        return cls(0xffffff)

    @classmethod
    def darkmode(cls: Type[CT]) -> CT:
        """Returns the color of the background when the color theme in Discord is set to dark mode"""
        return cls(0x363940)

    @classmethod
    def amoled(cls: Type[CT]) -> CT:
        """Returns the color of the background when the color theme in Discord is set to amoled mode. An alias of `black`"""
        return cls(0x000000)

    @classmethod
    def blurple_old(cls: Type[CT]) -> CT:
        """Returns the old Discord Blurple color"""
        return cls(0x7289da)

    @classmethod
    def blurple_new(cls: Type[CT]) -> CT:
        """Returns the new Discord Blurple color"""
        return cls(0x5865f2)

    default = black


Color = Colour


class MessageSelectMenuOption:
    def __init__(self, label: str, value: str, description: Optional[str] = None, emoji: Optional[PartialEmoji] = None, default: Optional[bool] = None):
        self.label: str = label
        self.value: str = value
        self.description: Optional[str] = description
        self.emoji: Optional[PartialEmoji] = emoji
        self.default: Optional[bool] = default

    def to_dict(self):
        settings = {
            "label": self.label,
            "value": self.value
        }

        if self.description:
            settings["description"] = self.description

        if self.emoji:
            if isinstance(self.emoji, PartialEmoji):
                settings["emoji"] = self.emoji.to_dict()

            elif isinstance(self.emoji, dict):
                settings["emoji"] = self.emoji

        if self.default:
            settings["default"] = self.default

        return settings


class MessageSelectMenu(BaseComponent):
    def __init__(self, *, min_values: Optional[int] = 1, max_values: Optional[int] = 1, disabled: Optional[bool] = False, custom_id: str):
        super().__init__(custom_id=custom_id)
        self.options: List[Union[MessageSelectMenuOption, dict]] = []
        self.type: str = 3
        self.min_values = min_values
        self.max_values = max_values
        self.disabled: bool = disabled

    def to_dict(self):
        settings = {
            "type": self.type,
            "options": self.options,
            "min_values": self.min_values,
            "max_values": self.max_values,
            "disabled": self.disabled,
            "custom_id": self.custom_id
        }
        return settings

    def add_options(self, options: List[MessageSelectMenuOption]):
        for option in options:

            if len(self.options) > 25:
                raise TooManySelectMenuOptions(
                    "You can only have 25 options in a select menu.")

            self.options.append(option.to_dict())
        return self

    def set_placeholder(self, placeholder: str):
        if not isinstance(placeholder, str):
            raise InvalidArgumentType("Placeholder must be a string.")

        self.settings["placeholder"] = placeholder
        return self

    def set_min_values(self, min: int):
        if not isinstance(min, int):
            raise InvalidArgumentType("Min must be an integer.")

        self.options["min_values"] = min
        return self

    def set_max_values(self, max: int):
        if not isinstance(max, int):
            raise InvalidArgumentType("Max must be an integer.")

        self.options["max_values"] = max
        return self

    def set_disabled(self, disabled: bool):
        self.disabled = disabled


class MessageTextInputComponent(BaseComponent):
    def __init__(self, *, custom_id: str, style: Union[int, str] = 1, label: str, min_length: Optional[int] = 10, max_length: Optional[int] = 4000, required: Optional[bool] = True, value: Optional[str] = None, placeholder: Optional[str] = None):
        super().__init__(custom_id=custom_id)
        VALID_STYLES = {
            "Short": 1,
            "Paragraph": 2
        }

        if isinstance(style, str):
            if style not in VALID_STYLES:
                raise InvalidComponentStyle(
                    "Style must be either 'Short' or 'Paragraph'.")
            style = VALID_STYLES[style]

        elif isinstance(style, int):
            if style not in VALID_STYLES.values():
                raise InvalidComponentStyle("Style must be either 1 or 2.")

        self.style: int = style
        self.label: str = label
        self.min_length: int = min_length
        self.max_length: int = max_length
        self.required: bool = required
        self.value: str = value
        self.placeholder: Optional[str] = placeholder

    def to_dict(self):
        settings: dict = {
            "type": self.type,
            "label": self.label,
            "min_length": self.min_length,
            "max_length": self.max_length,
            "required": self.required,
            "style": self.style,
        }

        if getattr(self, "value", None):
            settings["value"] = self.value

        if getattr(self, "placeholder", None):
            settings["placeholder"] = self.placeholder


class MessageButton(BaseComponent):
    def __init__(self, *, style: Optional[Union[int, str]] = 1, label: Optional[str] = None, emoji: Optional[Union[PartialEmoji, dict]] = None, url: Optional[str] = None, custom_id: str, disabled: bool = False):
        super().__init__(custom_id=custom_id)
        self.type: int = 2
        self.disabled = disabled

        valid_styles = {
            "PRIMARY": 1,
            "SECONDARY": 2,
            "SUCCESS": 3,
            "DANGER": 4,
            "LINK": 5
        }

        if isinstance(style, str):
            if style.upper() not in valid_styles:
                raise InvalidComponentStyle(
                    "Invalid button style. Style must be one of PRIMARY, SECONDARY, LINK, DANGER, or SUCCESS.")
            self.style: int = valid_styles[style.upper()]

        elif isinstance(style, int):
            if style not in valid_styles.values():
                raise InvalidComponentStyle(
                    "Invalid button style. Style must be in range 1 to 5 inclusive.")
            self.style: int = style

        if url:
            self.url: Optional[str] = url
            self.style: int = 5
        if emoji:
            self.emoji: Optional[Union[PartialEmoji, dict]] = emoji
        if label:
            self.label: Optional[str] = label

    def to_dict(self):
        settings = {
            "type": self.type,
            "custom_id": self.custom_id,
            "disabled": self.disabled,
            "style": self.style,
        }

        if getattr(self, "label", None):
            settings["label"] = self.label

        if getattr(self, "url", None):
            settings["url"] = self.url

        if getattr(self, "emoji", None):
            settings["emoji"] = self.emoji

        return settings

    def set_label(self, label: str):

        if not isinstance(label, str):
            raise InvalidArgumentType("Label must be a string.")

        if len(label) > 80:
            raise LabelIsTooBig("Label must be 80 characters or less.")

        self.settings["label"] = label
        return self

    def set_style(self, style: Union[int, str]):
        valid_styles = {
            "PRIMARY": 1,
            "SECONDARY": 2,
            "SUCCESS": 3,
            "DANGER": 4,
            "LINK": 5
        }
        if isinstance(style, str):
            if style.upper() not in valid_styles:
                raise InvalidComponentStyle(
                    "Invalid button style. Style must be one of PRIMARY, SECONDARY, LINK, DANGER, or SUCCESS.")
            self.settings["style"] = valid_styles[style.upper()]
            return self

        elif isinstance(style, int):
            if style not in valid_styles.values():
                raise InvalidComponentStyle(
                    "Invalid button style. Style must be in range 1 to 5 inclusive.")
            self.settings["style"] = style
            return self

    def set_emoji(self, emoji: Union[PartialEmoji, dict]):

        if isinstance(emoji, dict):
            self.settings["emoji"] = emoji
            return self

        elif isinstance(emoji, PartialEmoji):
            self.settings["emoji"] = emoji.data
            return self
        raise InvalidArgumentType(
            "Emoji must be a PartialEmoji or a dict that represents a PartialEmoji.")

    def set_url(self, url: str):

        if not isinstance(url, str):
            raise InvalidArgumentType("Url must be a string.")

        self.settings["url"] = url
        self.settings["style"] = 5
        return self


class MissingCustomId(Exception):
    ...


class MessageActionRow:
    def __init__(self, components: Optional[List[Union[MessageButton, MessageSelectMenu]]] = None):
        self.settings = {
            "type": 1,
            "components": components or []
        }
        self.type: int = 1
        self.components: List[Union[MessageTextInputComponent,
                                    MessageButton, MessageSelectMenu]] = components or []

    def to_dict(self):
        return {
            "type": self.type,
            "components": [component for component in self.components]
        }

    def add_components(self, components: List[Union[MessageButton, MessageSelectMenu]]):
        buttons = 0
        for component in components:
            if not component.custom_id:
                raise MissingCustomId(
                    f"You need to supply a custom id for the component {component}")

            if type(component) == MessageButton:
                buttons += 1

            elif buttons > 5:
                raise TooManyComponents("You can only have 5 buttons per row.")

            elif type(component) == MessageSelectMenu and buttons > 0:
                raise TooManyComponents(
                    "You can only have 1 select menu per row. No buttons along that select menu.")
            self.components.append(component.to_dict())
        return self


class Embed:  # Always wanted to make this class :D
    def __init__(self, *,
                 title: Optional[str] = None,
                 description: Optional[str] = None,
                 color: Optional[Colour] = None,
                 video: Optional[dict] = None,
                 timestamp: Optional[datetime.datetime] = None,
                 colour: Optional[Colour] = None,
                 url: Optional[str] = None,
                 type: Optional[int] = None,
                 footer: Optional[dict] = None,
                 image: Optional[dict] = None,
                 thumbnail: Optional[dict] = None,
                 provider: Optional[dict] = None,
                 author: Optional[dict] = None,
                 fields: Optional[List[dict]] = None,
                 ):
        self.type: int = type
        self.title: Optional[str] = title
        self.type: Optional[str] = type
        self.description: Optional[str] = description
        self.url: Optional[str] = url
        self.video: Optional[dict] = video
        self.timestamp: Optional[str] = timestamp
        self.color: Optional[Colour] = color or colour
        self.footer: Optional[str] = footer
        self.image: Optional[str] = image
        self.thumbnail: Optional[str] = thumbnail
        self.provider: Optional[str] = provider
        self.author: Optional[dict] = author
        self.fields: Optional[List[str]] = fields

    def add_field(self, *, name: str, value: str, inline: bool = False):
        self.fields.append({"name": name, "value": value, "inline": inline})

    def set_thumbnail(self, *, url: Optional[str] = None, proxy_url: Optional[str] = None, height: Optional[int] = None, width: Optional[int] = None):
        config = {
            "url": url
        }
        if proxy_url:
            config["proxy_url"] = proxy_url
        if height:
            config["height"] = height
        if width:
            config["width"] = width

        self.thumbnail = config

    def set_video(self, *, url: Optional[str] = None, proxy_url: Optional[str] = None, height: Optional[int] = None, width: Optional[int] = None):
        config = {
            "url": url
        }
        if proxy_url:
            config["proxy_url"] = proxy_url
        if height:
            config["height"] = height
        if width:
            config["width"] = width

        self.video = config

    def set_image(self, *, url: Optional[str] = None, proxy_url: Optional[str] = None, height: Optional[int] = None, width: Optional[int] = None):
        config = {
            "url": url
        }
        if proxy_url:
            config["proxy_url"] = proxy_url
        if height:
            config["height"] = height
        if width:
            config["width"] = width

        self.image = config

    def set_provider(self, *, name: Optional[str] = None, url: Optional[str] = None):
        config = {}
        if url:
            config["url"] = url
        if name:
            config["name"] = name
        self.provider = config

    def set_footer(self, *, text: Optional[str], icon_url: Optional[str] = None, proxy_icon_url: Optional[str] = None):
        payload = {}
        if text:
            payload["text"] = text
        if icon_url:
            payload["icon_url"] = icon_url
        if proxy_icon_url:
            payload["proxy_icon_url"] = proxy_icon_url
        self.footer = payload

    def set_author(self, name: Optional[str] = None, url: Optional[str] = None, icon_url: Optional[str] = None, proxy_icon_url: Optional[str] = None):
        payload = {}
        if name:
            payload["name"] = name
        if url:
            payload["url"] = url
        if icon_url:
            payload["icon_url"] = icon_url
        if proxy_icon_url:
            payload["proxy_icon_url"] = proxy_icon_url

        self.author = payload

    def set_fields(self, *, fields: List[dict]):
        self.fields = fields

    def set_color(self, *, colour: Colour):
        self.color = colour.value

    def set_timestamp(self, *, timestamp: datetime.datetime):
        self.timestamp = timestamp.isoformat()

    def set_title(self, title: Optional[str] = None):
        self.title = title

    def set_description(self, description: Optional[str] = None):
        self.description = description

    def set_url(self, url: Optional[str] = None):
        self.url = url

    def to_dict(self):
        final_product = {}

        if getattr(self, "title"):
            final_product["title"] = self.title
        if getattr(self, "description"):
            final_product["description"] = self.description
        if getattr(self, "url"):
            final_product["url"] = self.url
        if getattr(self, "timestamp"):
            final_product["timestamp"] = self.timestamp
        if getattr(self, "color"):
            final_product["color"] = self.color
        if getattr(self, "footer"):
            final_product["footer"] = self.footer
        if getattr(self, "image"):
            final_product["image"] = self.image
        if getattr(self, "thumbnail"):
            final_product["thumbnail"] = self.thumbnail
        if getattr(self, "video"):
            final_product["video"] = self.video
        if getattr(self, "provider"):
            final_product["provider"] = self.provider
        if getattr(self, "author"):
            final_product["author"] = self.author
        if getattr(self, "fields"):
            final_product["fields"] = self.fields

        return final_product


class RoleTag:
    def __init__(self, data: dict):
        self.bot_id: Optional[str] = data.get("bot_id")
        self.integration_id: Optional[str] = data.get("integration_id")
        self.premium_subscriber: Optional[bool] = data.get(
            "premium_subscriber")


class Role:
    def __init__(self, client, data: dict):
        self.data = data
        self.client = client
        self.id: str = data.get("id")
        self.name: str = data.get("name")
        self.color: int = data.get("color")
        self.hoist: bool = data.get("hoist")
        self.icon: Optional[str] = data.get("icon")
        self.unicode_emoji: Optional[str] = data.get("unicode_emoji")
        self.position: int = data.get("position")
        self.permissions: str = data.get("permissions")  # TODO: Permissions
        self.managed: bool = data.get("managed")
        self.mentionable: bool = data.get("mentionable")
        self.tags: RoleTag = RoleTag(self.data.get("tags"))


class Emoji:
    def __init__(self, client, data: dict, guild_id: str):
        self.client = client
        self.id: Optional[str] = data.get("id")
        self.name: Optional[str] = data.get("name")
        self.roles: List[Role] = [Role(role) for role in data.get("roles")]
        self.user: Optional[User] = User(
            data.get("user")) if "user" in data else None
        self.requires_colons: bool = data.get("require_colons")
        self.guild_id: str = data.get("guild_id")
        self.managed: bool = data.get("managed")
        self.guild_id: str = guild_id
        self.animated: bool = data.get("animated")
        self.available: bool = data.get("available")

    async def edit(self, *, name: Optional[str] = None, roles: Optional[List[Role]] = None, reason: Optional[str] = None):
        payload = {}

        if reason:
            payload["X-Audit-Log-Reason"] = reason

        if name:
            payload["name"] = name

        if roles:
            payload["roles"] = [role.id for role in roles]

        emoji = await self.client.http.patch(f"/guilds/{self.guild_id}/emojis/{self.id}", json=payload)
        return Emoji(self.client, emoji, self.guild_id)

    async def delete(self, *, reason: Optional[str] = None):
        payload = {}

        if reason:
            payload["X-Audit-Log-Reason"] = reason

        await self.client.http.delete(f"/guilds/{self.guild_id}/emojis/{self.id}", json=payload)


class DiscordAPIError(Exception):
    ...


class InvalidData(Exception):
    ...


class InvalidIntents(Exception):
    ...


class ShardingRequired(Exception):
    ...


class InvalidToken(Exception):
    ...


class UnhandledException(Exception):
    ...


class DisallowedIntents(Exception):
    ...


class BadRequest400(Exception):
    ...


class Unauthorized401(Exception):
    ...


class Forbidden403(Exception):
    ...


class NotFound404(Exception):
    ...


class MethodNotAllowed405(Exception):
    ...


class Ratelimited429(Exception):
    ...


class GateawayUnavailable502(Exception):
    ...


class InternalServerError5xx(Exception):
    ...


class TooManyComponents(Exception):
    ...


class InvalidComponentStyle(Exception):
    ...


class CustomIdIsTooBig(Exception):
    ...


class InvalidArgumentType(Exception):
    ...


class TooManySelectMenuOptions(Exception):
    ...


class LabelIsTooBig(Exception):
    ...


class ThreadArchived(Exception):
    ...


class WelcomeChannel:
    def __init__(self, data: dict):
        self.channel_id: str = data.get("channel_id")
        self.description: str = data.get("description")
        self.emoji_id: Optional[str] = data.get("emoji_id")
        self.emoji_name: Optional[str] = data.get("emoji_name")


class WelcomeScreen:
    def __init__(self, data: dict):
        self.description: Optional[str] = data.get("description")
        self.welcome_channels: List[WelcomeChannel] = [WelcomeChannel(
            welcome_channel) for welcome_channel in data.get("welcome_channels")]


class Guild:
    def __init__(self, client: Client, data: dict):
        self.client = client
        self.data: dict = data
        self.id: str = data.get("id")
        self.name: str = data.get("name")
        self.icon: Optional[str] = data.get("icon")
        self.icon_hash: Optional[str] = data.get("icon_hash")
        self.splash: Optional[str] = data.get("splash")
        self.discovery_splash: Optional[str] = data.get("discovery_splash")
        self.owner_id: str = data.get("owner_id")
        self.permissions: str = data.get("permissions")
        self.afk_channel_id: str = data.get("afk_channel_id")
        self.afk_timeout: int = data.get("afk_timeout")
        self.verification_level: str = "NONE" if data.get("verification_level") == 0 else "LOW" if data.get(
            "verification_level") == 1 else "MEDIUM" if data.get("verification_level") == 2 else "HIGH" if data.get("verification_level") == 3 else "VERY_HIGH"
        self.default_message_notifications: str = "ALL" if data.get(
            "default_message_notifications") == 0 else "MENTIONS"
        self.explicit_content_filter: str = "DISABLED" if data.get(
            "explicit_content_filter") == 0 else "MEMBERS_WITHOUT_ROLES" if data.get("explicit_content_filter") == 1 else "ALL_MEMBERS"
        self.roles: List[Role] = [Role(role) for role in data.get("roles")]
        self.emojis: List[Emoji] = [Emoji(emoji)
                                    for emoji in data.get("emojis")]
        self.features: List[str] = data.get("features")
        self.mfa_level: str = "NONE" if data.get(
            "mfa_level") == 0 else "ELEVATED"
        self.application_id: Optional[str] = data.get("application_id")
        self.system_channel_id: Optional[str] = data.get("system_channel_id")
        self.system_channel_flags: int = data.get("system_channel_flags")
        self.rules_channel_id: Optional[int] = data.get("rules_channel_id")
        self.joined_at: Optional[str] = data.get("joined_at")
        self.large: bool = data.get("large")
        self.unavailable: bool = data.get("unavailable")
        self.member_count: int = data.get("member_count")
        # self.voice_states: List[dict] = data["voice_states"]
        self.members: List[GuildMember] = [GuildMember(
            member) for member in data.get("members")]
        self.channels: List[GuildChannel] = [GuildChannel(
            channel) for channel in data.get("channels")]
        self.threads: List[Thread] = [
            Thread(thread) for thread in data.get("threads")]
        self.presences: List[dict] = data.get("presences")
        self.max_presences: int = data.get("max_presences")
        self.max_members: int = data.get("max_members")
        self.vanity_url_code: Optional[str] = data.get("vanity_url_code")
        self.description: Optional[str] = data.get("description")
        self.banner: Optional[str] = data.get("banner")
        self.premium_tier: int = data.get("premium_tier")
        self.premium_subscription_count: int = data.get(
            "premium_subscription_count")
        self.preferred_locale: str = data.get("preferred_locale")
        self.public_updates_channel_id: Optional[str] = data.get(
            "public_updates_channel_id")
        self.max_video_channel_users: Optional[int] = data.get(
            "max_video_channel_users")
        self.approximate_member_count: Optional[int] = data.get(
            "approximate_member_count")
        self.approximate_presence_count: Optional[int] = data.get(
            "approximate_presence_count")
        self.welcome_screen: Optional[WelcomeScreen] = WelcomeScreen(
            data.get("welcome_screen")) if data.get("welcome_screen") else None
        self.nsfw_level: int = data.get("nsfw_level")
        self.stage_instances: List[GuildStageChannel] = [
            GuildStageChannel(channel) for channel in data.get("stage_instances")]
        self.stickers: Optional[StickerItem] = StickerItem(
            data.get("stickers")) if data.get("stickers") else None


class GuildScheduledEvent:
    def __init__(self, client: Client, data: dict):
        self.id: str = data.get("id")
        self.client = client
        self.guild_id: str = data.get("guild_id")
        self.channel_id: Optional[str] = data.get("channel_id")
        self.creator_id: Optional[str] = data.get("creator_id")
        self.name: str = data.get("name")
        self.description: Optional[str] = data.get("description")
        self.scheduled_start_time: str = data.get("scheduled_start_time")
        self.scheduled_end_time: Optional[str] = data.get("scheduled_end_time")
        self.privacy_level: int = data.get("privacy_level")
        self.status: str = "SCHEDULED" if data.get("status") == 1 else "ACTIVE" if data.get(
            "status") == 2 else "COMPLETED" if data.get("status") == 3 else "CANCELLED"
        self.entity_type: str = "STAGE_INSTANCE" if data.get(
            "entity_type") == 1 else "VOICE" if data.get("entity_type") == 2 else "EXTERNAL"
        self.entity_id: str = data.get("entity_id")
        self.entity_metadata: dict = data.get("entity_metadata")
        self.creator: Optional[User] = User(data.get("creator"))
        self.user_count: Optional[int] = data.get("user_count")


class WebhookUser:
    def __init__(self, data: dict):
        self.webhook_id: str = data.get("webhook_id")
        self.username: str = data.get("username")
        self.avatar: str = data.get("avatar")


class Webhook:
    def __init__(self, client, data: dict = None):
        """
        Don't pass in data if you're making a webhook, the lib passes data to construct an already existing webhook
        """
        self.client = client
        self.data = data
        if data:
            self.id: str = data.get("id")
            self.type: str = "Incoming" if data.get(
                "type") == 1 else "Channel Follower" if data.get("type") == 2 else "Application"
            self.guild_id: Optional[str] = data.get("guild_id")
            self.channel_id: Optional[str] = data.get("channel_id")
            self.user: Optional[User] = User(client, data.get("user"))
            self.name: Optional[str] = data.get("name")
            self.avatar: Optional[str] = data.get("avatar")
            self.token: Optional[str] = data.get("token")
            self.application_id: Optional[str] = data.get("application_id")
            self.source_guild: Optional[PartialGuild] = PartialGuild(
                data.get("source_guild"))
            self.url: Optional[str] = data.get("url")


class BaseInteraction:
    def __init__(self, client, data: dict):
        self.id: str = data.get("id")
        self.client = client
        self.application_id: int = data.get("application_id")
        self.type: int = data.get("type")
        self.data: Optional[dict] = data.get("data")
        self.guild_id: Optional[str] = data.get("guild_id")
        self.channel_id: Optional[str] = data.get("channel_id")
        self.member: Optional[GuildMember] = GuildMember(data.get("member"))
        self.user: Optional[User] = User(data.get("user"))
        self.token: str = data.get("token")
        self.version: int = data.get("version")
        self.locale: Optional[str] = data.get("locale")
        self.guild_locale: Optional[str] = data.get("guild_locale")

    def is_ping(self):
        return self.type == 1

    def is_application_command(self):
        return self.type == 2

    def is_message_component(self):
        return self.type == 3

    def is_autocomplete(self):
        return self.type == 4

    async def reply(self, message_data: dict):
        response = await self.client.http.post(f"/interactions/{self.id}/{self.token}/callback", data=message_data)
        return await response.json()

    async def fetch_reply(self):
        response = await self.client.http.get(f"/webhooks/{self.application_id}/{self.token}/{self.token}/messages/@original")
        return await response.json()

    async def edit_reply(self, message_data: dict):
        response = await self.client.http.patch(f"/webhooks/{self.application_id}/{self.token}/messages/@original", data=message_data)
        return await response.json()

    async def delete_reply(self):
        response = await self.client.http.delete(f"/webhooks/{self.application_id}/{self.token}/messages/@original")
        return await response.json()

    async def followup(self, message_data: dict):
        response = await self.client.http.post(f"/webhooks/{self.application_id}/{self.token}", data=message_data)
        return await response.json()

    async def fetch_followup_message(self, message_id: str):
        response = await self.client.http.get(f"/webhooks/{self.application_id}/{self.token}/messages/{message_id}")
        return await response.json()

    async def edit_followup(self, message_id: str, message_data):
        response = await self.client.http.patch(f"/webhooks/{self.application_id}/{self.token}/messages/{message_id}", data=message_data)
        return await response.json()

    async def delete_followup(self, message_id: str):
        response = await self.client.http.delete(f"/webhooks/{self.application_id}/{self.token}/messages/{message_id}")
        return await response.json()


class Invite:
    def __init__(self, data: dict):
        self.code: str = data.get("code")
        self.guild: Optional[PartialGuild] = PartialGuild(
            data.get("guild")) if data.get("guild") else None
        self.channel: GuildChannel = GuildChannel(
            data.get("channel")) if data.get("channel") else None
        self.inviter: Optional[User] = User(
            data.get("inviter")) if data.get("inviter") else None
        self.target_type: int = data.get("target_type")
        self.target_user: Optional[User] = User(
            data.get("target_user")) if data.get("target_user") else None
        self.target_application: Optional[Application] = Application(
            data.get("target_application")) if data.get("target_application") else None
        self.approximate_presence_count: Optional[int] = data.get(
            "approximate_presence_count")
        self.approximate_member_count: Optional[int] = data.get(
            "approximate_member_count")
        self.expires_at: Optional[str] = data.get("expires_at")
        self.stage_instance: Optional[GuildStageChannel] = GuildStageChannel(
            data.get("stage_instance")) if data.get("stage_instance") else None
        self.guild_scheduled_event: Optional[GuildScheduledEvent] = GuildScheduledEvent(
            data.get("guild_scheduled_event"))
    # Dabmaster is gonna work on this


class GuildMember:
    def __init__(self, client, data: dict):
        self.data = data
        self.client = client
        # self.user: Optional[User] = User(data["user"]) or None
        self.nick: Optional[str] = data.get("nick")
        self.avatar: Optional[str] = data.get("avatar")
        self.role_ids: Optional[List[str]] = [
            role for role in data.get("roles", [])]
        self.joined_at: str = data.get("joined_at")
        self.premium_since: Optional[str] = data.get("premium_since")
        self.deaf: bool = data.get("deaf")
        self.mute: bool = data.get("mute")
        self.pending: Optional[bool] = data.get("pending")
        self.permissions: Optional[str] = data.get("permissions")
        self.communication_disabled_until: Optional[str] = data.get(
            "communication_disabled_until")


class MentionedChannel:
    def __init__(self, data: dict):
        self.id: str = data.get("id")
        self.guild_id: str = data.get("guild_id")
        self.type: int = data.get("type")
        self.name: str = data.get("name")


class MentionedUser(User):
    def __init__(self, client, data: dict):
        super().__init__(client, data)
        self.member = GuildMember(client, data.get("member"))


class MessageActivity:
    def __init__(self, data: dict):
        self.type: int = data.get("type")
        self.party_id: Optional[str] = data.get("party_id")


class AllowedMention:
    def __init__(self, allowed_mentions: List[str], replied_user: bool, roles: List[str], users: List[str]):
        self.data = {}
        self.data["parse"] = allowed_mentions
        self.data["replied_user"] = replied_user
        self.data["roles"] = roles
        self.data["users"] = users
        return self.data


class MessageInteraction:
    def __init__(self, client, data: dict):
        self.id: str = data.get("id")
        self.type: int = data.get("type")
        self.name: str = data.get("name")
        self.user: User = User(client, data.get("user"))
        self.member: GuildMember = GuildMember(client, data.get("member"))
        self.user: User

    def is_ping(self):
        return self.type == 1

    def is_application_command(self):
        return self.type == 2

    def is_message_component(self):
        return self.type == 3

    def is_autocomplete(self):
        return self.type == 4

    async def reply(self, message_data: dict):
        response = await self.client.http.post(f"/interactions/{self.id}/{self.token}/callback", data=message_data)
        return await response.json()

    async def fetch_reply(self):
        response = await self.client.http.get(f"/webhooks/{self.application_id}/{self.token}/{self.token}/messages/@original")
        return await response.json()

    async def edit_reply(self, message_data: dict):
        response = await self.client.http.patch(f"/webhooks/{self.application_id}/{self.token}/messages/@original", data=message_data)
        return await response.json()

    async def delete_reply(self):
        response = await self.client.http.delete(f"/webhooks/{self.application_id}/{self.token}/messages/@original")
        return await response.json()

    async def followup(self, message_data: dict):
        response = await self.client.http.post(f"/webhooks/{self.application_id}/{self.token}", data=message_data)
        return await response.json()

    async def fetch_followup_message(self, message_id: str):
        response = await self.client.http.get(f"/webhooks/{self.application_id}/{self.token}/messages/{message_id}")
        return await response.json()

    async def edit_followup(self, message_id: str, message_data):
        response = await self.client.http.patch(f"/webhooks/{self.application_id}/{self.token}/messages/{message_id}", data=message_data)
        return await response.json()

    async def delete_followup(self, message_id: str):
        response = await self.client.http.delete(f"/webhooks/{self.application_id}/{self.token}/messages/{message_id}")
        return await response.json()


class PartialUser:
    def __init__(self, data: dict):
        self.data: dict = data
        self.id: str = data.get("id")
        self.username: str = data.get("username")
        self.discriminator: str = data.get("discriminator")
        self.avatar: Optional[str] = data.get("avatar")


class PartialGuild:
    def __init__(self, data):
        self.data: dict = data
        self.id: str = data.get("id")
        self.name: str = data.get("name")
        self.permissions: int = int(data.get("permissions"))
        self.features: List[str] = data.get("features")


class SlashCommand(ApplicationCommand):
    def __init__(self, data: dict):
        super().__init__(data)
        self.options: Optional[List[Union[Subcommand, SubCommandGroup, StringOption, IntegerOption, BooleanOption, UserOption, ChannelOption, RoleOption, MentionableOption, NumberOption]]] = data.get(
            "options")  # Return the type hinted class later this will take too long and is very tedious, I'll probably get Copilot to do it for me lmao
        for option in self.options:
            option_type = option.get("type")
            if option_type == 1:
                return Subcommand(option)
            elif option_type == 2:
                return SubCommandGroup(option)
            elif option_type == 3:
                return StringOption(option)
            elif option_type == 4:
                return IntegerOption(option)
            elif option_type == 5:
                return BooleanOption(option)
            elif option_type == 6:
                return UserOption(option)
            elif option_type == 7:
                return ChannelOption(option)
            elif option_type == 8:
                return RoleOption(option)
            elif option_type == 9:
                return MentionableOption(option)
            elif option_type == 10:
                return NumberOption(option)

    def to_dict(self):
        json_options = []
        return {
            "name": self.name,
            "type": self.type,
            "description": self.description,
            "options": json_options,
        }


class TeamMember:
    def __init__(self, data: dict):
        self.data = data
        self.membership_state: int = data.get("membership_state")
        self.team_id: str = data.get("team_id")
        self.user: PartialUser = PartialUser(data.get("user"))


class Team:
    def __init__(self, data: dict):
        self.data = data
        self.icon: str = data.get("icon")
        self.id: str = data.get("id")
        self.members: List[TeamMember] = data.get("members")


class ClientUser():

    def __init__(self, client, data: dict):
        self.client = client
        self.data = data
        self.verified: bool = data.get("verified")
        self.username: str = data.get("username")
        self.mfa_enabled: bool = data.get("mfa_enabled")
        self.id: str = data.get("id")
        self.flags: int = data.get("flags")
        self.email: Optional[str] = data.get("email")
        self.discriminator: str = data.get("discriminator")
        self.bot: bool = data.get("bot")
        self.avatar: str = data.get("avatar")
        if not self.bot:  # if they're a user account
            # Yeah I'm keeping this as a print
            print("Warning: Self botting is against Discord ToS. You can get banned.")

    async def fetch(self):
        response = await self.client.http.get("users/@me")
        data = await response.json()
        super().__init__(data)  # Reinitialse the class with the new data.

    async def edit(self, *, username: Optional[str] = None, avatar: Optional[bytes] = None):
        payload = {}
        if username:
            payload["username"] = username
        if avatar:
            payload["avatar"] = _bytes_to_base64_data(avatar)
        response = await self.client.http.patch("users/@me", json=payload)
        data = await response.json()
        # Reinitialize the class with the new data, the full data.
        self.__init__(data)


class SourceChannel:
    def __init__(self, data: dict):
        self.id: str = data.get("id")
        self.name: str = data.get("name")


class Webhook:  # Not used for making webhooks.
    def __init__(self, client, data: dict):
        self.id: str = data.get("id")
        self.client = client
        self.type: int = "Incoming" if data.get("type") == 1 else "Channel Follower" if data.get("type") == 2 else "Application"
        self.guild_id: Optional[str] = data.get("guild_id")
        self.channel_id: Optional[str] = data.get("channel_id")
        self.user: Optional[WebhookUser] = WebhookUser(data.get("user"))
        self.name: Optional[str] = data.get("name")
        self.avatar: Optional[str] = data.get("avatar")
        self.token: str = data.get("token")
        self.application_id: Optional[str] = data.get("application_id")
        self.source_guild: Optional[PartialGuild] = PartialGuild(data.get("source_guild"))
        self.source_channel: Optional[SourceChannel] = SourceChannel(data.get("source_channel"))
        self.url: Optional[str] = data.get("url")

    


def compute_timedelta(dt: datetime.datetime):
    if dt.tzinfo is None:
        dt = dt.astimezone()
    now = datetime.datetime.now(datetime.timezone.utc)
    return max((dt - now).total_seconds(), 0)


async def sleep_until(when: Union[datetime.datetime, int, float], result: Optional[T] = None) -> Optional[T]:
    if when == datetime.datetime:
        delta = compute_timedelta(when)

    return await asyncio.sleep(delta if when == datetime.datetime else when, result)


def remove_markdown(text: str, *, ignore_links: bool = True) -> str:
    def replacement(match):
        groupdict = match.groupdict()
        return groupdict.get('url', '')

    regex = _MARKDOWN_STOCK_REGEX
    if ignore_links:
        regex = f'(?:{_URL_REGEX}|{regex})'
    return re.sub(regex, replacement, text, 0, re.MULTILINE)


def escape_markdown(text: str, *, as_needed: bool = False, ignore_links: bool = True) -> str:
    if not as_needed:

        def replacement(match):
            groupdict = match.groupdict()
            is_url = groupdict.get('url')
            if is_url:
                return is_url
            return '\\' + groupdict['markdown']

        regex = _MARKDOWN_STOCK_REGEX
        if ignore_links:
            regex = f'(?:{_URL_REGEX}|{regex})'
        return re.sub(regex, replacement, text, 0, re.MULTILINE)
    else:
        text = re.sub(r'\\', r'\\\\', text)
        return _MARKDOWN_ESCAPE_REGEX.sub(r'\\\1', text)


def escape_mentions(text: str) -> str:
    return re.sub(r'@(everyone|here|[!&]?[0-9]{17,20})', '@\u200b\\1', text)


def utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


class Intents:
    def __init__(self, *, intents: Optional[int] = None):
        self.value = intents or 0

    @property
    def guilds(self):
        self.value += 1 << 0
        return self

    @property
    def guild_members(self):
        self.value += 1 << 1
        return self

    @property
    def guild_bans(self):
        self.value += 1 << 2
        return self

    @property
    def guild_emojis_and_stickers(self):
        self.value += 1 << 3
        return self

    @property
    def guild_integrations(self):
        self.value += 1 << 4
        return self

    @property
    def guild_webhooks(self):
        self.value += 1 << 5
        return self

    @property
    def guild_invites(self):
        self.value += 1 << 6
        return self

    @property
    def guild_voice_states(self):
        self.value += 1 << 7
        return self

    @property
    def guild_presences(self):
        self.value += 1 << 8
        return self

    @property
    def guild_messages(self):
        self.value += 1 << 9
        return self

    @property
    def guild_message_reactions(self):
        self.value += 1 << 10
        return self

    @property
    def guild_message_typing(self):
        self.value += 1 << 11
        return self

    @property
    def direct_messages(self):
        self.value += 1 << 12
        return self

    @property
    def direct_message_reactions(self):
        self.value += 1 << 13
        return self

    @property
    def direct_message_typing(self):
        self.value += 1 << 14
        return self

    @property
    def all(self):
        for attr in dir(self):
            if attr not in ["value", "all", "none", "remove_value", "add_intent"]:
                getattr(self, attr)
        return self

    @property
    def none(self):
        self.value = 0

    def remove_intent(self, intent: str) -> int:
        try:
            attr = getattr(self, intent.lower())
        except AttributeError:
            raise InvalidIntents(
                f"Intent {intent.lower()} is not a valid intent.")
        self.value -= attr.value
        return self.value

    def add_intent(self, intent: str) -> int:
        try:
            attr = getattr(self, intent)
        except AttributeError:
            raise InvalidIntents(f"Intent {intent} is not a valid intent.")
        self.value += attr
        return self.value

    @property
    def message_content(self):
        self.value += 1 << 15
        return self

    # TODO: Add some presets such as "Moderation", "Logging" etc.


class Permission:
    def __init__(self, *, bit: int = 0):
        self.value = bit

    @property
    def create_instant_invite(self):
        self.value += 1 << 0
        return self

    @property
    def kick_members(self):
        self.value += 1 << 1
        return self

    @property
    def ban_members(self):
        self.value += 1 << 2
        return self

    @property
    def administrator(self):
        self.value += 1 << 3
        return self

    @property
    def manage_channels(self):
        self.value += 1 << 4
        return self

    @property
    def manage_guild(self):
        self.value += 1 << 5
        return self

    @property
    def add_reactions(self):
        self.value += 1 << 6
        return self

    @property
    def view_audit_log(self):
        self.value += 1 << 7
        return self

    @property
    def priority_speaker(self):
        self.value += 1 << 8
        return self

    @property
    def stream(self):
        self.value += 1 << 9
        return self

    @property
    def read_messages(self):
        self.value += 1 << 10
        return self

    @property
    def send_messages(self):
        self.value += 1 << 11
        return self

    @property
    def send_tts_messages(self):
        self.value += 1 << 12
        return self

    @property
    def manage_messages(self):
        self.value += 1 << 13
        return self

    @property
    def embed_links(self):
        self.value += 1 << 14
        return self

    @property
    def attach_files(self):
        self.value += 1 << 15
        return self

    @property
    def read_message_history(self):
        self.value += 1 << 16
        return self

    @property
    def mention_everyone(self):
        self.value += 1 << 17
        return self

    @property
    def use_external_emojis(self):
        self.value += 1 << 18
        return self

    @property
    def connect(self):
        self.value += 1 << 20
        return self

    @property
    def speak(self):
        self.value += 1 << 21
        return self

    @property
    def mute_members(self):
        self.value += 1 << 22
        return self

    @property
    def deafen_members(self):
        self.value += 1 << 23
        return self

    @property
    def move_members(self):
        self.value += 1 << 24
        return self

    @property
    def use_voice_activation(self):
        self.value += 1 << 25
        return self

    @property
    def change_nickname(self):
        self.value += 1 << 26
        return self

    @property
    def manage_nicknames(self):
        self.value += 1 << 27
        return self

    @property
    def manage_roles(self):
        self.value += 1 << 28
        return self

    @property
    def manage_webhooks(self):
        self.value += 1 << 29
        return self

    @property
    def manage_emojis_and_stickers(self):
        self.value += 1 << 30
        return self

    @property
    def use_application_commands(self):
        self.value += 1 << 31
        return self

    @property
    def request_to_speak(self):
        self.value += 1 << 32
        return self

    @property
    def manage_events(self):
        self.value += 1 << 33
        return self

    @property
    def manage_threads(self):
        self.value += 1 << 34
        return self

    @property
    def create_public_threads(self):
        self.value += 1 << 35
        return self

    @property
    def create_private_threads(self):
        self.value += 1 << 36
        return self

    @property
    def use_external_stickers(self):
        self.value += 1 << 37
        return self

    @property
    def send_messages_in_threads(self):
        self.value += 1 << 38
        return self

    @property
    def start_embedded_activities(self):
        self.value += 1 << 39
        return self

    @property
    def moderator_members(self):
        self.value += 1 << 40
        return self

class VoiceState:
    def __init__(self, client, data: dict):
        self.data: dict = data
        self.guild_id: Optional[str] = data.get("guild_id")
        self.channel_id: str = data.get("channel_id")
        self.user_id: str = data.get("user_id")
        self.member: Optional[GuildMember] = GuildMember(client, data.get("member")) if data.get("member") else None
        self.session_id: str = data.get("session_id")
        self.deaf: bool = data.get("deaf")
        self.mute: bool = data.get("mute")
        self.self_deaf: bool = data.get("self_deaf")
        self.self_mute: bool = data.get("self_mute")
        self.self_stream: Optional[bool] = data.get("self_stream")
        self.self_video: bool = data.get("self_video")
        self.suppress: bool = data.get("suppress")
        self.request_to_speak_timestamp: datetime.datetime = datetime.datetime.fromisoformat(data.get("request_to_speak_timestamp"))

class Paginator:
    def __init__(self, *, pages: List[Embed]):
        self.current_index: int = 0
        self.pages = pages
    def back(self):
        return self.pages[self.current_index - 1]
    def forward(self):
        return self.pages[self.current_index + 1]
    def current(self):
        return self.pages[self.current_index]
    def add_page(self, page: Embed):
        self.pages.append(page)
    def remove_page(self, page: Embed):
        self.pages = filter(lambda embed: embed != page, self.pages)
    def current(self) -> Embed:
        return self.pages[self.current_index] 