import {
  WebSocketGateway,
  WebSocketServer,
  SubscribeMessage,
  MessageBody,
  ConnectedSocket,
} from '@nestjs/websockets';
import { Server, Socket } from 'socket.io';
import { ChatService } from './chat.service';
import { CreateMessageDto } from './dto/create-message.dto';

@WebSocketGateway({ cors: { origin: '*' } })
export class ChatGateway {
  @WebSocketServer()
  server: Server;

  constructor(private chatService: ChatService) {}

  @SubscribeMessage('handleConnection')
  async handleConnection(client: Socket) {
    const userId = client.handshake.query.userId as string;
    if (userId) {
      console.log(`User joined room: user_${userId}`);
      client.join(`user_${userId}`);
    }
  }

  @SubscribeMessage('sendMessage')
  async handleMessage(client: Socket, createMessageDto: CreateMessageDto) {
    try {
      const message = await this.chatService.sendMessage(createMessageDto, this.server);

      // Emit confirmation or message to client
      client.emit('messageSent', message);
    } catch (error) {
      client.emit('messageError', { error: error.message });
    }
  }
}
