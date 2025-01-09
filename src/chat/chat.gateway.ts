import { CreateMessageDto } from './dto/create-message.dto';
import { PrismaService } from 'src/prisma.service';
import { WebSocketGateway, WebSocketServer, SubscribeMessage, MessageBody, ConnectedSocket } from '@nestjs/websockets';
import { Server, Socket } from 'socket.io';

@WebSocketGateway({ cors: true })
export class ChatGateway {
  @WebSocketServer()
  server: Server;

  constructor(private prisma: PrismaService) {}

  @SubscribeMessage('sendMessage')
  async handleMessage(
    @MessageBody() createMessageDto: CreateMessageDto,
    @ConnectedSocket() client: Socket,
  ) {
    try {
      // Check if chatId exists and is valid
      const chat = await this.prisma.chat.findUnique({
        where: { id: createMessageDto.chatId },
      });

      if (!chat) {
        throw new Error('Chat not found');
      }

      // Create message with sender and optionally receiver
      const message = await this.prisma.message.create({
        data: {
          content: createMessageDto.content,
          senderId: createMessageDto.senderId,
          chatId: createMessageDto.chatId,
          receiverId: createMessageDto.receiverId,
        },
        include: {
          sender: true,
          receiver: true,  // Include the receiver in the result if provided
          chat: true,
        },
      });

      this.server.emit('message', message);
    } catch (error) {
      console.error('Error handling message:', error);
    }
  }
}
