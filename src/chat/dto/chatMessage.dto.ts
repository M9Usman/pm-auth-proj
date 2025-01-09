import { IsInt, IsNotEmpty, IsOptional, IsArray, IsString } from 'class-validator';

export class ChatMessageDto {
  @IsArray()
  @IsString({ each: true })
  @IsNotEmpty()
  messages: string[];  // Array of messages

  @IsInt()
  @IsNotEmpty()
  senderId: number;

  @IsInt()
  @IsNotEmpty()
  chatId: number;  // This should be included in every message request

  @IsInt()
  @IsOptional()
  receiverId?: number;  // Optional, only for one-to-one chats

  @IsString()
  type?: string;  // Type can be set to "one-to-one" or "group"
}
