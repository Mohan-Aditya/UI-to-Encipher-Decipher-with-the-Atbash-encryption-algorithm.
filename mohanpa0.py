1.	#Section-1 : defining function for encryption#
2.	def Mohanencipher(plaintext):
3.	    ciphertext = ""
4.	    for c in range(len(plaintext)):
5.	        char = plaintext[c]
6.	        if (char.isupper()):
7.	            ciphertext += chr(90-(ord(char)-65) % 26)
8.	        elif char==" ":
9.	            ciphertext += " "
10.	        elif (char.islower()):
11.	            ciphertext += chr(122-(ord(char)-97)%26)
12.	        else:
13.	            ciphertext += char
14.	    return ciphertext
15.	
16.	#Section-2 : defining function for decryption#
17.	def Mohandecipher(ciphertext):
18.	    plaintext = ""
19.	    for i in range(len(ciphertext)):
20.	        char = ciphertext[i]
21.	        if (char.isupper()):
22.	            plaintext += chr(90-(ord(char)-65) % 26)
23.	        elif char==" ":
24.	            plaintext += " "
25.	        elif (char.islower()):
26.	            plaintext += chr(122-(ord(char)-97)%26)
27.	        else:
28.	            plaintext += char
29.	    return plaintext
30.	# modules to import
31.	import tkinter as tk
32.	from tkinter import ttk
33.	
34.	#Section-3 : tkinter labels, functions for buttons, etc#
35.	class MohanCipher:
36.	
37.	    def __init__(self, root):
38.	
39.	        self.plain_text = tk.StringVar(root, value="")
40.	        self.cipher_text = tk.StringVar(root, value="")
41.	        self.key = tk.IntVar(root)
42.	# creates Tkinter window
43.	        # creating root object 
44.	        #root = Tk() 
45.	  
46.	# defining size of window 
47.	        #root.geometry("1200x6000") 
48.	        # creates window title
49.	        root.title("Mohan - Cipher PA0 Application")
50.	        # allows for window to be resized
51.	        root.resizable(True,True)
52.	         # window background
53.	        root.configure(background='gold')
54.	       
55.	        style = ttk.Style() 
56.	        style.configure("TLabel", font = "Serif 20", padding=20)
57.	        style.configure("TButton", font="Serif 10", padding=5)
58.	        style.configure("TEntry", font="Serif 36", padding=20)
59.	
60.	        self.plain_label = tk.Label(root, text="Plain text", fg="green",font = ('arial', 12, 'bold'), 
61.			 bd = 16, anchor = "w").grid(row=1, column=1)
62.	# seperated the .grid as it was causing a None type error
63.	        self.plain_entry = tk.Entry(root,font = ('arial', 16, 'bold'), textvariable = Msg, bd = 10, insertwidth = 4, bg = "powder blue", justify = 'right',width=32)
64.	        self.plain_entry.grid(row=2, column=0, rowspan=2 , columnspan=2)
65.	        self.plain_clear = tk.Button(root, text="Clear",fg="brown",
66.	                                    command=lambda: self.clear('plain')).grid(row=4, column=1)
67.	
68.	
69.	# buttons to encrypt / decrypt
70.	        self.encipher_button = Button(root, text="Encrypt ->",
71.	                                    command=lambda: self.encipher_press()).grid(row=2, column=3)
72.	        self.decipher_button = Button(root, text="<- Decrypt",
73.	                                    command=lambda: self.decipher_press()).grid(row=3, column=3)
74.	
75.	        self.cipher_label = tk.Label(root, text="Cipher text", fg="red",font = ('arial', 12, 'bold'), 
76.			 bd = 16, anchor = "w").grid(row=1, column=4)
77.	
78.	        self.cipher_entry = Entry(root,
79.	                                    font = ('arial', 16, 'bold'), 
80.				textvariable = Result, bd = 10, insertwidth = 4, 
81.						bg = "powder blue", justify = 'left',width=32)
82.	        self.cipher_entry.grid(row=2, column=4, rowspan=2 , columnspan=2)
83.	
84.	        self.cipher_clear = tk.Button(root, text="Clear",fg="brown",
85.	                                    command=lambda: self.clear('cipher')).grid(row=4, column=4)
86.	
87.	
88.	
89.	    def clear(self, str_val):
90.	        if str_val == 'cipher':
91.	            self.cipher_entry.delete(0, 'end')
92.	        else:
93.	            self.plain_entry.delete(0, 'end')
94.	
95.	    def encipher_press(self):
96.	        cipher_text = Mohanencipher(self.plain_entry.get())
97.	        self.cipher_entry.delete(0, "end")
98.	        self.cipher_entry.insert(0, cipher_text)
99.	
100.	    def decipher_press(self):
101.	        plain_text = Mohandecipher(self.cipher_entry.get())
102.	        self.plain_entry.delete(0, "end")
103.	        self.plain_entry.insert(0, plain_text)
104.	
105.	#making window alive
106.	root = tk.Tk()
107.	Mohan = MohanCipher(root)
108.	root.mainloop()
