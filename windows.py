import base64
import decimal
import os
import random
import string
import sys
from tkinter import *
from tkinter import ttk, filedialog, messagebox
import rsa
from Crypto.Cipher import AES, DES


class Windows:
    def __init__(self):

        self.suffix = None
        self.file = None

        self.main = Tk()  # 引入tk
        self.main.geometry("300x300")  # 设置大小
        # 文件操作的控制器
        self.select_path = StringVar()  # 选择文件
        self.file_show = Label(self.main, text="文件路径：")
        self.file_route = Entry(self.main, textvariable=self.select_path)
        self.file_button = Button(self.main, text="选择单个文件", command=self.select_file)

        # 单选加密解密的控制器
        self.Enc_dec_mobile = StringVar()
        self.operate = Label(self.main, text="操作: ")
        self.encryption = ttk.Radiobutton(self.main, text="加密", variable=self.Enc_dec_mobile, value='加密')
        self.decrypt = ttk.Radiobutton(self.main, text="解密", variable=self.Enc_dec_mobile, value="解密")

        self.radio_mobile = StringVar()  # 加解密方法
        self.method_operate = Label(self.main, text="选择方式: ")
        self.rsa_way = ttk.Radiobutton(self.main, text="rsa", variable=self.radio_mobile, value='rsa_way')
        self.aes = ttk.Radiobutton(self.main, text="aes", variable=self.radio_mobile, value="aes_way")
        self.des = ttk.Radiobutton(self.main, text="des", variable=self.radio_mobile, value="des_way")
        self.md5 = ttk.Radiobutton(self.main, text="混合加密", variable=self.radio_mobile, value="mix_way")

        self.confirm = Button(self.main, text="确认", command=self.submit)

        # 设置位置
        # 选择文件位置
        self.file_show.place(x=0,y=0)
        self.file_route.place(x=60, y=0)
        self.file_button.place(x=200,y=0)

        # 加密选择位置
        self.method_operate.place(x=0,y=80)
        self.rsa_way.place(x=60, y=80)
        self.aes.place(x=120, y=80)
        self.des.place(x=60, y=120)
        self.md5.place(x=120, y=120)

        # 操作位置
        self.operate.place(x=0, y=150)
        self.encryption.place(x=40, y=150)
        self.decrypt.place(x=90, y=150)

        # 确认按钮
        self.confirm.place(x=220,y=170)

        self.main.mainloop()

    def select_file(self):
        # 单个文件选择
        selected_file_path = filedialog.askopenfilename()  # 使用askopenfilename函数选择单个文件
        self.select_path.set(selected_file_path)

    def mix_select_file(self):
        mix_file = filedialog
        mix_selected_file_path = mix_file.askopenfilename()  # 使用askopenfilename函数选择单个文件
        self.mix_path.set(mix_selected_file_path)

    def submit(self):
        file_path = self.file_route.get()  # 选择文件路径
        radio = self.radio_mobile.get()  # 加解密方式
        enc_dec = self.Enc_dec_mobile.get()  # 加解密
        try:  # 判断是否有这个文件
            with open(file_path, 'rb') as f:
                # 读取文件二进制
                self.file = f.read()
                self.suffix = os.path.splitext(file_path)[-1]
        except FileNotFoundError:
            messagebox.showwarning(title='提示', message='请选择存在的文件')
        else:
            if not file_path:
                messagebox.showwarning(title='提示', message='请选择文件')
            elif not radio:
                messagebox.showwarning(title='提示', message='请选择加解密方式')
            elif not enc_dec:
                messagebox.showwarning(title='提示', message='请选择加密/解密')
            elif radio == 'rsa_way' and enc_dec == "加密":
                self.window_rsa_way()
            elif radio == 'rsa_way' and enc_dec == "解密":
                self.rsa_decrypt_fun()
            elif radio == 'aes_way' and enc_dec == "加密":
                self.aes_encryption_fun()
            elif radio == 'aes_way' and enc_dec == "解密":
                self.aes_decrypt_fun()
            elif radio == 'des_way' and enc_dec == "加密":
                self.des_encryption_fun()
            elif radio == 'des_way' and enc_dec == "解密":
                self.des_decrypt_fun()
            elif radio == 'mix_way' and enc_dec == "加密":
                self.mix_encryption()
            elif radio == 'mix_way' and enc_dec == "解密":
                self.mix_decrypt_fun()

    def rsa_encryption_sumit(self):
        input_public_key = self.Publictext_enc_input.get("1.0", "end-1c") # 获取输入框的公钥
        if input_public_key is None:
            messagebox.showwarning(title='提示', message='请输入公钥进行加密')
        else:
            try:
                pk = rsa.PublicKey.load_pkcs1(input_public_key)  # 通过公钥创建加密对象
                length = len(self.file)  # 获取文件长度
                val_list = []
                # 循环 每117个字节进行加密
                for i in range(0, length, 117):
                    tpl = self.file[i:i + 117]
                    val = rsa.encrypt(tpl, pk)
                    val_list.append(val)
                # 添加到二进制里面
                ret = b''.join(val_list)
                # 打开文件 保存
                with open('rsa加密文件%s' % self.suffix, 'wb') as rsa_file_write:
                    rsa_file_write.write(ret)
                path = sys.path[0] + '\\ras加密文件'
                messagebox.showwarning(title='提示', message='加密成功,文件保存在%s' % path)
            except:
                messagebox.showwarning(title='提示', message='请输入正确的公钥')

    def rsa_decryption_sumit(self):
        input_decrypt_key = self.Publictext_dec_input.get("1.0", "end-1c")
        if input_decrypt_key == '':
            messagebox.showwarning(title='提示', message='请输入秘钥进行解密')
        else:
            try:
                pk = rsa.PrivateKey.load_pkcs1(input_decrypt_key)
                length = len(self.file)
                val_list = []
                # 每128字节进行解密
                for i in range(0, length, 128):
                    tpl = self.file[i:i + 128]
                    val = rsa.decrypt(tpl, pk)
                    val_list.append(val)
                ret = b''.join(val_list)
                with open('rsa解密文件%s' % self.suffix, 'wb') as rsa_file_write:
                    rsa_file_write.write(ret)
                path = sys.path[0] + '\\ras解密文件'
                messagebox.showwarning(title='提示', message='解密成功,文件保存在%s' % path)
            except:
                messagebox.showwarning(title='提示', message='请输入正确的秘钥')

    def rsa_key(self):
        public, private = rsa.newkeys(1024)  # 生成公钥、私钥
        with open("./private.pem", "wb") as x:  # 保存私钥
            x.write(private.save_pkcs1())
        with open("./public.pem", "wb") as x:  # 保存公钥
            x.write(public.save_pkcs1())
        messagebox.showwarning(title='提示', message='rsa公钥私钥生成在代码目录下')

    def aes_encryption_sumit(self):
        # 获取秘钥
        ase_pwd = self.aes_pwd.get().encode('utf-8')
        if ase_pwd == '':
            messagebox.showwarning(title='提示', message='请输入秘钥')
        elif len(ase_pwd) != 16:
            messagebox.showwarning(title='提示', message='请输入16位的秘钥')
        else:
            # 创建解密对象
            aes = AES.new(ase_pwd, AES.MODE_ECB)
            # 解密
            den_text = aes.decrypt(self.file)
            with open('aes解密文件%s' % self.suffix, 'wb') as f:
                f.write(den_text)
            messagebox.showwarning(title='提示', message='aes解密成功，文件在代码目录下')

    def des_encryption_sumit(self):
        des_pwd = self.des_pwd.get().encode('utf-8')
        if des_pwd == '':
            messagebox.showwarning(title='提示', message='请输入秘钥')
        elif len(des_pwd) != 8:
            messagebox.showwarning(title='提示', message='请输入16位的秘钥')
        else:
            crpytor = DES.new(des_pwd, DES.MODE_CBC, b'\x9a\xf8\xad\xeb.\xb7B\xe1' )
            decrypt_data = crpytor.decrypt(self.file)
            with open('des解密文件%s' % self.suffix, 'wb') as f:
                f.write(decrypt_data)
            messagebox.showwarning(title='提示', message='des解密成功，文件在代码目录下')

    def aes_encryption_fun(self):
        len_file = len(self.file)
        # 秘钥
        pwd = self.random_str(16).encode('utf-8')
        aes = AES.new(pwd, AES.MODE_ECB)
        val_list = []
        for i in range(0, len_file, 16):
            tpl = self.file[i:i + 16]
            if len(tpl) != 16:
                for count in range(0, 16 - len(tpl)):
                    tpl += b'\0'
            en_text = aes.encrypt(tpl)
            val_list.append(en_text)
        ret = b''.join(val_list)
        path = sys.path[0] + '\\aes加密文件'
        with open('aes加密文件%s' % self.suffix, 'wb') as f:
            f.write(ret)
        with open('aes秘钥.txt','wb') as f:
            f.write(pwd)
            messagebox.showwarning(title='提示', message='加密成功,加密文件以及秘钥保存在%s' % path)

    def rsa_encryption_fun(self):
        self.main_ras_enc = Tk()
        self.main_ras_enc.geometry("350x400")
        self.Publictext_enc_input = Text(self.main_ras_enc, width=50)
        self.Public_Key_enc = Button(self.main_ras_enc, text="确认加密", command=self.rsa_encryption_sumit)
        self.Publictext_enc_input.place(x=-0,y=0)
        self.Public_Key_enc.place(x=160, y=320)
        self.main_ras_enc.mainloop()

    def aes_decrypt_fun(self):
        self.aes_decrypt_main = Tk()
        self.aes_decrypt_main.geometry("250x50")

        self.aes_text = Label(self.aes_decrypt_main, text="输入秘钥：")
        self.aes_pwd = Entry(self.aes_decrypt_main)
        self.aes_sum = Button(self.aes_decrypt_main, text="确认", command=self.aes_encryption_sumit)
        self.aes_text.place(x=0, y=0)
        self.aes_pwd.place(x=60, y=0)
        self.aes_sum.place(x=100,y=25)
        self.aes_decrypt_main.mainloop()

    def window_rsa_way(self):
        self.main_rsa = Tk()  # 引入tk
        self.main_rsa.geometry("300x100")  # 设置大小
        self.Public_Key = Button(self.main_rsa, text="生成公钥私钥", command=self.rsa_key)
        self.Public_Key2 = Button(self.main_rsa, text="使用已有公钥加密", command=self.rsa_encryption_fun)
        self.Public_Key.place(x=50, y=20)
        self.Public_Key2.place(x=170, y=20)
        self.main_rsa.mainloop()

    def rsa_decrypt_fun(self):
        print('解密')
        self.main_ras_dec = Tk()
        self.main_ras_dec.geometry("350x400")
        self.Publictext_dec_input = Text(self.main_ras_dec, width=50)
        self.Public_Key_dec = Button(self.main_ras_dec, text="解密", command=self.rsa_decryption_sumit)
        self.Publictext_dec_input.place(x=-0, y=0)
        self.Public_Key_dec.place(x=160, y=320)
        self.main_ras_dec.mainloop()

    def des_encryption_fun(self):
        len_file = len(self.file)
        # 秘钥
        pwd = self.random_str(8).encode('utf-8')
        iv = b'\x9a\xf8\xad\xeb.\xb7B\xe1'  # 初始化向量，固定8个字节长度
        crpytor = DES.new(pwd, DES.MODE_CBC, iv)
        val_list = []
        for i in range(0, len_file, 8):
            tpl = self.file[i:i + 8]
            if len(tpl) != 8:
                for count in range(0, 8 - len(tpl)):
                    tpl += b'\0'
            en_text = crpytor.encrypt(tpl)  # 对数据进行加密
            val_list.append(en_text)
        ret = b''.join(val_list)
        path = sys.path[0] + '\\des加密文件'
        with open('des加密文件%s' % self.suffix, 'wb') as f:
            f.write(ret)
        with open('des秘钥.txt', 'wb') as f:
            f.write(pwd)
            messagebox.showwarning(title='提示', message='加密成功,加密文件以及秘钥保存在%s' % path)

    def des_decrypt_fun(self):
        self.main_des_dec = Tk()
        self.main_des_dec.geometry("250x50")
        self.des_text = Label(self.main_des_dec, text="输入秘钥：")
        self.des_pwd = Entry(self.main_des_dec)
        self.des_sum = Button(self.main_des_dec, text="确认", command=self.des_encryption_sumit)
        self.des_text.place(x=0, y=0)
        self.des_pwd.place(x=60, y=0)
        self.des_sum.place(x=100, y=25)
        self.main_des_dec.mainloop()

    def mix_encryption(self):
        len_file = len(self.file)
        # 秘钥
        aes_pwd = self.random_str(16).encode('utf-8')
        print('aes_pwd:%s' % aes_pwd)
        des_pwd = self.random_str(8).encode('utf-8')
        print('des_pwd:%s' % des_pwd)
        iv = b'\x9a\xf8\xad\xeb.\xb7B\xe1'
        aes = AES.new(aes_pwd, AES.MODE_ECB)
        val_list = []
        for i in range(0, len_file, 16):
            tpl = self.file[i:i + 16]
            if len(tpl) != 16:
                for count in range(0, 16 - len(tpl)):
                    tpl += b'\0'
            en_text = aes.encrypt(tpl)
            val_list.append(en_text)
        ret = b''.join(val_list)
        path = sys.path[0] + '\\混合加密文件'
        with open('混合加密文件%s' % self.suffix, 'wb') as f:
            f.write(ret)
        des = DES.new(des_pwd, DES.MODE_CBC, iv)
        decrypt_data = des.encrypt(aes_pwd)
        print("加密后aes: %s" % decrypt_data)
        mix_pwd = base64.b64encode(decrypt_data+des_pwd)
        with open('混合加密秘钥.pem', 'wb') as f:
            f.write(mix_pwd)
        messagebox.showwarning(title='提示', message='加密成功,加密文件以及秘钥保存在%s' % path)

    def mix_decrypt_fun(self):
        self.mix_decrypt_main = Tk()
        self.mix_decrypt_main.geometry("250x50")
        self.mix_text = Label(self.mix_decrypt_main, text="输入秘钥：")
        self.mix_pwd = Entry(self.mix_decrypt_main)
        self.mix_sum = Button(self.mix_decrypt_main, text="确认", command=self.mix_decrypt_sumit)
        self.mix_text.place(x=0, y=0)
        self.mix_pwd.place(x=60, y=0)
        self.mix_sum.place(x=100, y=25)

        self.mix_decrypt_main.mainloop()

    def mix_decrypt_sumit(self):
        pwd = self.mix_pwd.get()
        base_dec = base64.b64decode(pwd)
        key = base_dec[16:]  # 密钥,固定8个字节长度
        iv = b'\x9a\xf8\xad\xeb.\xb7B\xe1'
        crpytor = DES.new(key, DES.MODE_CBC, iv)
        aes_pwd = crpytor.decrypt(base_dec[0:16])
        aes = AES.new(aes_pwd, AES.MODE_ECB)
        text = aes.decrypt(self.file)
        path = sys.path[0] + '\\混合解密文件'
        with open('混合解密文件%s' % self.suffix, 'wb') as f:
            f.write(text)
        messagebox.showwarning(title='提示', message='解密成功保存在%s' % path)

    def returnFloat(self, arg):
        new_arg = int(arg)
        result = decimal.Decimal(str(arg)) - decimal.Decimal(str(new_arg))
        result = float(result)
        return result

    def random_str(self, n):
        # 生成指定长度字符串
        s = string.ascii_letters + string.ascii_uppercase + string.digits
        return ''.join(random.sample(s, n))


Windows()