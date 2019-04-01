from tkinter import *
from tkinter.ttk import OptionMenu, Notebook
from tkinter import filedialog, messagebox
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES, DES, DES3, Blowfish, PKCS1_OAEP
from Cryptodome.PublicKey import RSA, ECC, DSA, ElGamal
from Cryptodome.Signature import pkcs1_15, pss, DSS
from Cryptodome.Hash import MD5, SHA1, SHA224, SHA256, SHA384, SHA512, RIPEMD160

class StorageButton(Button):
	def __init__(self, *args, **kwargs):
		self.path = ""
		self.state = False
		kwargs["bg"] = "orangered"
		kwargs["text"] = args[1]
		kwargs["width"] = 16
		kwargs["justify"] = CENTER
		kwargs["command"] = self.action
		super().__init__(args[0], **kwargs)

	def get(self):
		return self.val if self.state is True else False

	def action(self, path = None):
		# Открыть файл
		if path is None:
			path = filedialog.askopenfilename(initialdir = ".")
		if path:
			self.path = path
			with open(self.path, "rb") as f:
				text = f.read()
			self.val = text
			self.state = True
			self.config(bg = "lime")

	def reset(self):
		self.val = ""
		self.path = ""
		self.state = False
		self.config(state = "normal", bg = "orangered")

class HoukagoFrameTime(Frame):
	def __init__(self, *args, **kwargs):
		super().__init__(args[0], **kwargs)
		self.algs = args[1]

		# Блок выбора алгоритма
		self.frm_alg = Frame(self)
		self.frm_alg.pack(side = TOP)
		# Заголовок
		self.lbl_alg = Label(self.frm_alg, text = "Алгоритм:")
		self.lbl_alg.pack(side = LEFT)
		# Выбор алгоритма
		self.cur_alg = StringVar()
		self.cur_alg.trace("w", self.alg_changed)
		self.ddl_alg = OptionMenu(self.frm_alg, self.cur_alg, *list(self.algs.keys()))
		self.ddl_alg.pack(side = LEFT)
	
	def alg_changed(self, *args):
		pass

class app(Tk):
	class sym(HoukagoFrameTime):
		def __init__(self, *args, **kwargs):
			algs = { "": None, "AES": { "obj": AES, "key": 32 },
					"Blowfish": { "obj": Blowfish, "key": 56 },
					"DES": { "obj": DES, "key": 8 },
					"3DES": { "obj": DES3, "key": 24 } }
			super().__init__(args[0], algs, **kwargs)
			self.cur_alg.set("AES")
			self.res = ""

			# Блок ввода парамеров 1
			self.frm_params1 = Frame(self)
			self.frm_params1.pack(side = TOP)
			# Хранилище ключа
			self.btn_key = StorageButton(self.frm_params1, "Ключ")
			self.btn_key.pack(side = LEFT, padx = 5)
			# Кнопка генерации ключа
			self.btn_generate = StorageButton(self.frm_params1, "Сгенерировать")
			self.btn_generate.config(bg = "SystemButtonFace", command = self.btn_gen_key)
			self.btn_generate.pack(side = LEFT)
			# Блок ввода парамеров 2
			self.frm_params2 = Frame(self)
			self.frm_params2.pack(side = TOP, pady = 5)
			# Хранилище вектора
			self.btn_vect = StorageButton(self.frm_params2, "Вектор")
			self.btn_vect.pack(side = LEFT, padx = 5)
			# Прочитать ввод из файла
			self.btn_open = StorageButton(self.frm_params2, "Из файла")
			self.btn_open.config(bg = "SystemButtonFace", command = self.btn_read_from_file)
			self.btn_open.pack(side = LEFT)

			# Блок с кнопками
			self.frm_buttons = Frame(self)
			self.frm_buttons.pack(side = TOP, fill = X)
			# Кнопка "зашифровать"
			self.btn_encode = Button(self.frm_buttons, text = "Зашифровать", command = lambda: self.btn_action(1))
			self.btn_encode.pack(side = LEFT, expand = YES, fill = X, padx = 5)
			# Кнопка "расшифровать"
			self.btn_decode = Button(self.frm_buttons, text = "Дешифровать", command = lambda: self.btn_action(2))
			self.btn_decode.pack(side = LEFT, expand = YES, fill = X, padx = 5)

			# Блок с вводом и выводом
			self.frm_input = Frame(self)
			self.frm_input.pack(side = LEFT, expand = YES, fill = BOTH, pady = 5)
			# Поле ввода
			self.txt_input = Text(self.frm_input)
			self.txt_input.pack(side = LEFT, expand = YES, fill = BOTH, padx = 5)
			# Ползунок для просмотра всего поля ввода
			self.scrl_input = Scrollbar(self.txt_input, command = self.txt_input.yview)
			self.txt_input.config(yscrollcommand = self.scrl_input.set)
			self.scrl_input.pack(side = RIGHT, fill = Y)
			# Поле вывода
			self.txt_output = Text(self.frm_input, bg = "SystemButtonFace")
			self.txt_output.bind("<KeyRelease>", lambda ev: self.set_output(self.res))
			self.txt_output.pack(side = LEFT, expand = YES, fill = BOTH, padx = 5)
			# Ползунок для просмотра всего поля
			self.scrl_output = Scrollbar(self.txt_output, command = self.txt_output.yview)
			self.txt_output.config(yscrollcommand = self.scrl_output.set)
			self.scrl_output.pack(side = RIGHT, fill = Y)

		def alg_changed(self, *args):
			# Определяем текущий алгоритм
			alg = self.cur_alg.get()
			if not alg:
				return
			alg = self.algs[alg]
			# Меняем параметры контроллеров
			self.btn_key.reset()
			self.btn_vect.reset()
			self.res = ""
			self.set_output(self.res)

		def set_input(self, text):
			# Изменить контент в поле ввода
			self.txt_input.delete("0.0", END)
			self.txt_input.insert("0.0", text)

		def set_output(self, text):
			# Изменить контент в поле вывода
			self.txt_output.delete("0.0", END)
			self.txt_output.insert("0.0", text)

		def btn_gen_key(self):
			# Проверить выбран ли алгоритм
			alg = self.cur_alg.get()
			if not alg:
				messagebox.showerror("Ошибка", "Выберите алгоритм из списка")
				return
			#alg = self.algs[alg]
			# Сгенерировать ключ для алгоритма
			if alg == "3DES":
				while True:
					try:
						key = DES3.adjust_key_parity(get_random_bytes(24))
						break
					except ValueError:
						pass
			else:
				key = get_random_bytes(self.algs[alg]["key"])
			# Сохранить ключ
			with open("key", "wb") as f:
				f.write(key)
			self.btn_key.action("key")

		def btn_read_from_file(self):
			# Открыть файл
			path = filedialog.askopenfilename(initialdir = ".")
			if path:
				with open(path, "rb") as f:
					text = f.read()
				self.set_input(text.decode("latin-1")) # вывод прочитанной бинарки в поле ввода

		def btn_action(self, event):
			# Проверить выбран ли алгоритм
			alg = self.cur_alg.get()
			if not alg:
				messagebox.showerror("Ошибка", "Выберите алгоритм из списка")
				return
			alg = self.algs[alg]
			# Получить ввод, ключ и вектор
			text = self.txt_input.get("0.0", END)[:-1].encode("latin-1") # прочитать ввод в поле ввода
			key = self.btn_key.get()
			vect = self.btn_vect.get()
			if key is False:
				messagebox.showerror("Ошибка", "Для работы необходим ключ")
				return
			if event == 2 and vect is False:
				messagebox.showerror("Ошибка", "Для работы необходим вектор инициализации")
				return
			# Сделать работу
			if event == 1:
				cipher = alg["obj"].new(key, alg["obj"].MODE_CFB)
				res = cipher.encrypt(pad(text, alg["obj"].block_size))
				with open("vect", "wb") as f:
					f.write(cipher.iv)
				self.btn_vect.action("vect")
				self.res = res.decode("latin-1")
			else:
				cipher = alg["obj"].new(key, alg["obj"].MODE_CFB, iv = vect)
				res = unpad(cipher.decrypt(text), alg["obj"].block_size)
				self.res = res
			with open("sym", "wb") as f:
				f.write(res)
			self.set_output(self.res)

	class asym(HoukagoFrameTime):
		def __init__(self, *args, **kwargs):
			algs = { "": None, "PKCS#1 OAEP": { "obj": PKCS1_OAEP } }
			super().__init__(args[0], algs, **kwargs)
			self.cur_alg.set("PKCS#1 OAEP")
			self.len = "2048"

			# Блок ввода парамеров 1
			self.frm_params1 = Frame(self)
			self.frm_params1.pack(side = TOP)
			# Заголовок для выбора размера ключа
			self.lbl_len = Label(self.frm_params1, text = "Размер ключа:")
			self.lbl_len.pack(side = LEFT)
			# Ползунок изменения размера ключа
			self.key_len = StringVar()
			self.spn_len = Spinbox(self.frm_params1, textvariable = self.key_len, values = (1024, 2048, 3072), width = 5, justify = CENTER)
			self.key_len.set(self.len)
			self.spn_len.pack(side = LEFT, padx = 5)
			# Кнопка генерации ключа
			self.btn_generate = StorageButton(self.frm_params1, "Сгенерировать")
			self.btn_generate.config(bg = "SystemButtonFace", command = self.btn_gen_keys)
			self.btn_generate.pack(side = LEFT)

			# Блок ввода парамеров 2
			self.frm_params2 = Frame(self)
			self.frm_params2.pack(side = TOP, pady = 5)
			# Хранилище ключа
			self.btn_prvt_key = StorageButton(self.frm_params2, "Закрытый ключ")
			self.btn_prvt_key.pack(side = LEFT, padx = 5)
			# Хранилище ключа
			self.btn_pub_key = StorageButton(self.frm_params2, "Открытый ключ")
			self.btn_pub_key.pack(side = LEFT)

			# Блок с кнопками
			self.frm_buttons = Frame(self)
			self.frm_buttons.pack(side = TOP, fill = X)
			# Кнопка "зашифровать"
			self.btn_encode = Button(self.frm_buttons, text = "Зашифровать сообщение", command = self.btn_encrypt)
			self.btn_encode.pack(side = LEFT, expand = YES, fill = X, padx = 5)
			# Кнопка "расшифровать"
			self.btn_decode = Button(self.frm_buttons, text = "Дешифровать файл", command = self.btn_decrypt)
			self.btn_decode.pack(side = LEFT, expand = YES, fill = X, padx = 5)

			# Поле ввода/вывода
			self.txt_box = Text(self)
			self.txt_box.pack(side = LEFT, expand = YES, fill = BOTH, padx = 5, pady = 5)
			# Ползунок для просмотра всего поля ввода
			self.scrl_input = Scrollbar(self.txt_box, command = self.txt_box.yview)
			self.txt_box.config(yscrollcommand = self.scrl_input.set)
			self.scrl_input.pack(side = RIGHT, fill = Y)

		def set_text(self, text):
			# Изменить контент в поле ввода/вывода
			self.txt_box.delete("0.0", END)
			self.txt_box.insert("0.0", text)

		def btn_gen_keys(self):
			# Сгенерировать ключи
			key = RSA.generate(int(self.len))
			prvt_key = key.export_key()
			pub_key = key.publickey().export_key()
			# Сохранить ключи
			with open("key.prvt", "wb") as f:
				f.write(prvt_key)
			self.btn_prvt_key.action("key.prvt")
			with open("key.pub", "wb") as f:
				f.write(pub_key)
			self.btn_pub_key.action("key.pub")

		def btn_encrypt(self):
			# Проверить выбран ли алгоритм
			alg = self.cur_alg.get()
			if not alg:
				messagebox.showerror("Ошибка", "Выберите алгоритм из списка")
				return
			alg = self.algs[alg]
			# Получить ввод, ключ и вектор
			text = self.txt_box.get("0.0", END)[:-1].encode("utf-8") # прочитать ввод в поле ввода
			key = self.btn_pub_key.get()
			if key is False:
				messagebox.showerror("Ошибка", "Для работы необходим ключ")
				return
			key = RSA.import_key(key)
			# Сделать работу
			cipher = alg["obj"].new(key)
			res = cipher.encrypt(text)
			with open("asym", "wb") as f:
				f.write(res)
			self.set_text(res.decode("latin-1"))

		def btn_decrypt(self):
			# Проверить выбран ли алгоритм
			alg = self.cur_alg.get()
			if not alg:
				messagebox.showerror("Ошибка", "Выберите алгоритм из списка")
				return
			alg = self.algs[alg]
			# Открыть файл
			path = filedialog.askopenfilename(initialdir = ".")
			if path:
				with open(path, "rb") as f:
					text = f.read()
				self.set_text(text.decode("latin-1")) # вывод прочитанной бинарки в поле ввода
			# Получаем закрытый ключ
			key = self.btn_prvt_key.get()
			if key is False:
				messagebox.showerror("Ошибка", "Для работы необходим ключ")
				return
			key = RSA.import_key(key)
			# Сделать работу
			cipher = alg["obj"].new(key)
			res = cipher.decrypt(text)
			with open("asym", "wb") as f:
				f.write(res)
			self.set_text(res.decode("latin-1"))

	class signer(HoukagoFrameTime):
		def __init__(self, *args, **kwargs):
			algs = { "": None,
					"RSASSA-PKCS1": { "obj": pkcs1_15, "key": RSA, "mode": None },
					"RSASSA-PSS": { "obj": pss, "key": RSA, "mode": None } }
			super().__init__(args[0], algs, **kwargs)
			self.cur_alg.set("RSASSA-PKCS1")

			# Блок ввода парамеров
			self.frm_params = Frame(self)
			self.frm_params.pack(side = TOP, pady = 5)
			# Закртый ключ (private key)
			self.btn_prvt_key = StorageButton(self.frm_params, "Закрытый ключ")
			self.btn_prvt_key.pack(side = LEFT, padx = 5)
			# Открытый ключ (public key)
			self.btn_pub_key = StorageButton(self.frm_params, "Открытый ключ")
			self.btn_pub_key.pack(side = LEFT)

			# Блок ввода парамеров
			self.frm_buttons = Frame(self)
			self.frm_buttons.pack(side = TOP)
			# Прочитать ввод из файла
			self.btn_sign = StorageButton(self.frm_buttons, "Подписать")
			self.btn_sign.config(bg = "SystemButtonFace", command = self.btn_sign_action)
			self.btn_sign.pack(side = LEFT, padx = 5)
			# Прочитать ввод из файла
			self.btn_verify = StorageButton(self.frm_buttons, "Проверить")
			self.btn_verify.config(bg = "SystemButtonFace", command = self.btn_verify_action)
			self.btn_verify.pack(side = LEFT)

			# Вывод результата
			self.lbl_output = Label(self, text = "Выберите файл", bg = "SystemButtonFace")
			self.lbl_output.config(width = 30, height = 5)
			self.lbl_output.pack(side = TOP, expand = YES, fill = None)

		def btn_sign_action(self):
			# Проверить выбран ли алгоритм
			alg = self.cur_alg.get()
			if not alg:
				messagebox.showerror("Ошибка", "Выберите алгоритм из списка")
				return
			alg = self.algs[alg]
			# Проверить наличие закрытого ключа
			key = self.btn_prvt_key.get()
			if not key:
				messagebox.showerror("Ошибка", "Для подписания необходим закрытый ключ")
				return
			# Открыть файл
			path = filedialog.askopenfilename(initialdir = ".")
			if not path:
				return
			with open(path, "rb") as f:
				text = f.read()
			# Подписать
			h = SHA256.new(text)
			key = alg["key"].import_key(key)
			signer = alg["obj"].new(key) if alg["mode"] is None else alg["obj"].new(key, alg["mode"])
			signature = signer.sign(h)
			# Сохранение подписанного файла
			with open("sign", "wb") as f:
				f.write(signature)
			self.lbl_output.config(text = "Файл подписан", bg = "lime")
	
		def btn_verify_action(self):
			# Проверить выбран ли алгоритм
			alg = self.cur_alg.get()
			if not alg:
				messagebox.showerror("Ошибка", "Выберите алгоритм из списка")
				return
			alg = self.algs[alg]
			# Проверить наличие открытого ключа
			key = self.btn_pub_key.get()
			if not key:
				messagebox.showerror("Ошибка", "Для проверки подписи необходим публичный ключ")
				return
			# Открыть файл
			path = filedialog.askopenfilename(initialdir = ".")
			if not path:
				return
			with open(path, "rb") as f:
				text = f.read()
			with open("sign", "rb") as f:
				signature = f.read()
			# Проверить подпись
			h = SHA256.new(text)
			key = alg["key"].import_key(key)
			verifyer = alg["obj"].new(key) if alg["mode"] is None else alg["obj"].new(key, alg["mode"])
			try:
				verifyer.verify(h, signature)
				self.lbl_output.config(text = "Подпись подлина", bg = "lime")
			except:
				self.lbl_output.config(text = "Подпись не подлина", bg = "orangered")

	class hasher(HoukagoFrameTime):
		def __init__(self, *args, **kwargs):
			algs = { "": None, "MD5": MD5, "SHA-1": SHA1,
					"SHA-224": SHA224, "SHA-256": SHA256,
					"SHA-384": SHA384, "SHA-512": SHA512,
					"RIPEMD-160": RIPEMD160 }
			super().__init__(args[0], algs, **kwargs)
			self.cur_alg.set("MD5")

			# Блок с кнопками
			self.frm_buttons = Frame(self)
			self.frm_buttons.pack(side = TOP, fill = X, pady = 5)
			# Кнопка "открыть файл"
			self.btn_open = Button(self.frm_buttons, text = "Файл...", command = self.btn_open_action)
			self.btn_open.pack(side = LEFT, expand = YES, fill = X, padx = 5)
			# Кнопка "получить хэш"
			self.btn_encode = Button(self.frm_buttons, text = "Получить хэш", command = self.btn_encode_action)
			self.btn_encode.pack(side = LEFT, expand = YES, fill = X, padx = 5)

			# Блок ввода
			self.frm_input = Frame(self)
			self.frm_input.pack(side = TOP, expand = YES, fill = BOTH, padx = 5)
			# Поле ввода
			self.txt_input = Text(self.frm_input)
			self.txt_input.pack(side = LEFT, expand = YES, fill = BOTH)
			# Ползунок для просмотра всего поля
			self.scrl_input = Scrollbar(self.txt_input, command = self.txt_input.yview)
			self.txt_input.config(yscrollcommand = self.scrl_input.set)
			self.scrl_input.pack(side = RIGHT, fill = Y)

			# Блок вывода
			self.frm_output = Frame(self)
			self.frm_output.pack(side = TOP, fill = X, padx = 5, pady = 5)
			# Поле вывода
			self.txt_output = Entry(self.frm_output, justify = CENTER, state = "readonly")
			self.txt_output.pack(side = TOP, expand = YES, fill = X)

		def set_input(self, text):
			# Изменить контент в поле ввода
			self.txt_input.delete("0.0", END)
			self.txt_input.insert("0.0", text)

		def set_output(self, text):
			# Изменить контент в поле вывода
			self.txt_output.config(state = "normal")
			self.txt_output.delete(0, END)
			self.txt_output.insert(0, text)
			self.txt_output.config(state = "readonly")

		def btn_open_action(self):
			# Открыть файл
			path = filedialog.askopenfilename(initialdir = ".")
			if path:
				with open(path, "rb") as f:
					text = f.read()
				self.set_input(text.decode("latin-1")) # вывод прочитанной бинарки в поле ввода

		def btn_encode_action(self):
			# Начать хэшить по черному
			alg = self.cur_alg.get()
			if not alg:
				messagebox.showerror("Ошибка", "Выберите алгоритм из списка")
				return
			text = self.txt_input.get("0.0", END)[:-1].encode("latin-1") # прочитать ввод в поле ввода
			h = self.algs[alg].new()
			h.update(text)
			res = h.hexdigest().upper()
			res = "".join([ str(res[i]) + " " if i % 8 == 7 else res[i] for i in range(len(res)) ]).strip()
			self.set_output(res)
			fname = "hash"
			with open(fname, "w") as f:
				f.write(res)
			if len(res) > 82:
				messagebox.showinfo("Информация", "Результат слишком большой для отображения.\nПолный результат сохранен в файле %s" % fname)

	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)
		self.title("Криптодел")
		self.resizable(False, False)
		self.geometry("%dx%d" % (550, 300))

		self.root = Notebook(self)
		self.root.pack(side = TOP, expand = YES, fill = BOTH, padx = 5, pady = 5)

		self.sym_page = self.sym(self.root)
		self.root.add(self.sym_page, text = "Симметричные алгоритмы")

		self.asym_page = self.asym(self.root)
		self.root.add(self.asym_page, text = "Асимметричные алгоритмы")

		self.sign_page = self.signer(self.root)
		self.root.add(self.sign_page, text = "Цифровая подпись")

		self.hash_page = self.hasher(self.root)
		self.root.add(self.hash_page, text = "Хэширование")

if __name__ == "__main__": app().mainloop()
