FROM node:20-alpine

# Thiết lập thư mục làm việc trong container
WORKDIR /app

# Sao chép package.json và package-lock.json vào container
COPY package*.json ./

# Cài đặt các phụ thuộc bản an toàn
RUN npm install

# Sao chép toàn bộ mã nguồn dự án vào container
COPY . .

# Mở cổng 3000 bên trong container
EXPOSE 3000

# Thiết lập biến môi trường
ENV NODE_ENV=development
ENV DUMMY_SECRET="LAB_PATCHED_SECRET_DO_NOT_USE_67890"

# Lệnh khởi chạy ứng dụng Next.js
CMD ["npm", "run", "dev"]