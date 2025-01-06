/*
  Warnings:

  - You are about to drop the column `userId` on the `ResetPassword` table. All the data in the column will be lost.

*/
-- DropForeignKey
ALTER TABLE "ResetPassword" DROP CONSTRAINT "ResetPassword_userId_fkey";

-- DropIndex
DROP INDEX "ResetPassword_token_userId_key";

-- DropIndex
DROP INDEX "reset_password_email_idx";

-- AlterTable
ALTER TABLE "ResetPassword" DROP COLUMN "userId";
