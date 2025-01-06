/*
  Warnings:

  - You are about to drop the column `email` on the `ResetPassword` table. All the data in the column will be lost.
  - Added the required column `userId` to the `ResetPassword` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE "ResetPassword" DROP COLUMN "email",
ADD COLUMN     "userId" INTEGER NOT NULL;
