    import { IsString, IsInt, IsOptional, IsNotEmpty } from 'class-validator';

    export class CreateMessageDto {
    @IsString()
    content: string;

    @IsInt()
    chatId: number;

    @IsInt()
    @IsNotEmpty()
    senderId: number;

    @IsInt()
    @IsOptional()  // Marks receiverId as optional
    receiverId?: number | null;
    }
