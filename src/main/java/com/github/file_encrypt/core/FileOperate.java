/*
 * Copyright 2019-2119 gao_xianglong@sina.com
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.github.file_encrypt.core;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.util.Base64Utils;

import javax.annotation.PostConstruct;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.*;
import java.util.stream.Stream;

/**
 * 文件操作核心类
 *
 * @author gao_xianglong@sina.com
 * @version 0.1-SNAPSHOT
 * @date created in 2020/4/8 11:49 上午
 */
@Service
public class FileOperate {
    /**
     * 原路径或文件
     */
    private String sourcePath;
    /**
     * 目标路径或文件
     */
    private String targetPath;
    /**
     * 秘钥
     */
    private String key;
    /**
     * 状态0位加密,1为解密
     */
    private byte type;
    /**
     * 大文件每次加密的运算大小，100MB
     */
    private final int BEFORE_MAX_SIZE = 0x6400000;
    /**
     * 大文件每次解密的运算大小
     */
    private final int AFTER_MAX_SIZE = 0x855556c;
    private List<String[]> sourcePathList = new ArrayList<>(32);
    private final String KEY_ALGORITHM = "AES";
    private final String DEFAULT_CIPHER_ALGORITHM = "AES/ECB/PKCS5Padding";//加密算法
    private Logger log = LoggerFactory.getLogger("");

    public FileOperate() {
        sourcePath = System.getProperty("from");
        targetPath = System.getProperty("to");
        key = System.getProperty("key");
        String type_ = System.getProperty("type");
        Objects.requireNonNull(type_, () -> "type can't be null");
        type = Byte.parseByte(type_);
        log.info("sourcePath:{},targetPath:{},type:{},key:{}", sourcePath, targetPath, type, key);
    }

    private void run() {
        Objects.requireNonNull(key, () -> "key can't be null");
        Objects.requireNonNull(sourcePath, () -> "sourcePath can't be null");
        targetPath = Objects.isNull(targetPath) ? sourcePath : targetPath;
        File file = new File(sourcePath);
        if (file.isFile()) {
            sourcePathList.add(split(sourcePath));
        } else {
            getPaths(file);
        }
        if (!sourcePathList.isEmpty()) {
            sourcePathList.forEach(path -> {
                MappedByteBuffer b1 = null;
                String sn = String.format("%s/%s", path[0], path[1]);
                String tn = String.format("%s/%s-%s", path[0], path[1], System.currentTimeMillis());//删除源文件之前,目标文件名加上时间戳
                try (FileChannel c1 = new RandomAccessFile(sn, "rw").getChannel();
                     FileChannel c2 = new RandomAccessFile(tn, "rw").getChannel()) {
                    long size = c1.size();
                    b1 = c1.map(FileChannel.MapMode.READ_ONLY, 0, size);
                    int maxSize = 0 == type ? BEFORE_MAX_SIZE : AFTER_MAX_SIZE;//加密前/后读取的文件大小是不一样的
                    while (true) {
                        if (size < maxSize) {//小文件，一次性读完
                            run(new byte[(int) size], b1, 0, c2);
                            break;
                        }
                        int position = b1.position();//buf读写起始位置
                        int limit = b1.limit();//buf读写结束位置
                        int surplus = limit - position;//buf剩余位置
                        run(new byte[surplus > maxSize ? maxSize : surplus], b1, c2.size(), c2);
                        if (surplus < maxSize) break;
                    }
                    log.info("file:[{}{}] {} success!", path[0], path[1], 0 == type ? "encrypt" : "decrypt");
                } catch (Exception e) {
                    log.error("{} fail!", 0 == type ? "encrypt" : "decrypt", e);
                } finally {
                    try {
                        Files.delete(Path.of(sn));//完成加解密后,删除源文件
                    } catch (IOException e) {
                        log.error("source file:[{}] delete fail!", sn);
                    }
                    new File(tn).renameTo(new File(sn));//删除源文件后,将目标文件名更改为源文件名
                }
            });
        }
    }

    public static void main(String[] agr) {
        System.setProperty("from", "/Users/johngao/Desktop/test");
        System.setProperty("key", "123456");
        System.setProperty("type", "1");
        FileOperate v = new FileOperate();
        v.run();
    }

    /**
     * 执行加/解密并落盘
     *
     * @param value
     * @param b1
     * @param position
     * @param channel
     * @throws Exception
     */
    private void run(byte[] value, MappedByteBuffer b1, long position, FileChannel channel) throws Exception {
        b1.get(value);
        value = 0 == type ? encrypt(value) : decrypt(value);//0加密,1解密
        MappedByteBuffer b2 = channel.map(FileChannel.MapMode.READ_WRITE, position, value.length);
        b2.put(value);
    }

    /**
     * 对目标文件进行AES加密处理
     *
     * @param content
     * @return
     * @throws Exception
     */
    private byte[] encrypt(byte[] content) throws Exception {
        Objects.requireNonNull(content);
        Cipher cipher = Cipher.getInstance(DEFAULT_CIPHER_ALGORITHM);//创建密码器
        cipher.init(Cipher.ENCRYPT_MODE, getSecretKey());//设置为加密模式
        return Base64Utils.encode(cipher.doFinal(content));//加密/Base64编码
    }

    /**
     * 对目标文件进行AES解密处理
     *
     * @param content
     * @return
     * @throws Exception
     */
    private byte[] decrypt(byte[] content) throws Exception {
        Objects.requireNonNull(content);
        Cipher cipher = Cipher.getInstance(DEFAULT_CIPHER_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, getSecretKey());//设置为解密模式
        return cipher.doFinal(Base64Utils.decode(content));//Base64解码后进行解密处理
    }

    private SecretKeySpec secretKeySpec;

    /**
     * 生成AES秘钥
     *
     * @return
     * @throws Exception
     */
    private SecretKeySpec getSecretKey() throws Exception {
        if (Objects.isNull(secretKeySpec)) {
            SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
            sr.setSeed(key.getBytes());
            KeyGenerator keyGenerator = KeyGenerator.getInstance(KEY_ALGORITHM);
            //keyGenerator.init(128, new SecureRandom(key.getBytes()));//AES密钥长度为128
            keyGenerator.init(128, sr);//非windows操作系统使用此秘钥生成方式,否则会报Given final block not properly padded. Such issues can arise if a bad key is used during decryption.
            secretKeySpec = new SecretKeySpec(keyGenerator.generateKey().getEncoded(), KEY_ALGORITHM);
        }
        return secretKeySpec;
    }


    /**
     * 如果目标地址是路径则获取路径下所有的文件
     *
     * @param file
     */
    private void getPaths(File file) {
        Stream.of(file.listFiles()).forEach(x -> {
            if (x.isFile()) {
                sourcePathList.add(split(x.getPath()));
            } else {
                getPaths(x);
            }
        });
    }

    /**
     * 拆分目录和文件名
     *
     * @param str
     * @return
     */
    private String[] split(String str) {
        String t1[] = str.split("\\/");
        String t2 = t1[t1.length - 1];
        return new String[]{str.split(t2)[0], t2};
    }

    @PostConstruct
    public void accept() {
        run();
    }
}
