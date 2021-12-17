#Alessandro Canevaro
#Graphic interface for PyChat® 7
#07/01/2016

#Libraries
from tkinter import *
from tkinter import ttk

#Constant
Symbols = [['Smile', ['☹', '☺', '☻']] ,
           ['Trademark', ['™', '℠', '©', '®', '℗']],
           ['Valute', ['$', '¢', '£', '¥', '₤', '€']],
           ['Math', ['½', '⅓', '¾', '⅔', '≅', '≈', '≠', '≤', '≥']],
           ['Carte', ['♦', '♠', '♥', '♣', '♢', '♤', '♡', '♧']],
           ['Mani', ['☚', '☛', '☜', '☝', '☞', '☟', '✌']],
           ['Musica', ['♪', '♫', '♩', '♬', '♭', '♮', '♯']],
           ['Meteo', ['☼', '☀', '☁', '☂', '☾', '℃', '℉', 'ϟ']],
           ['Credenze', ['☪', '☮', 'Ⓐ', '☭']],
           ['Altro', ['♋', '♂', '♀', '✉', '✎', '☑','✂', '☎', '⌚', '⌛', '∞', '←', '↑', '→', '↓', '⚽']]]

settings = {'Theme':'clam', 'MMcolor':'#FACC2E', 'OMcolor':'blue', 'MCcolor':'#FF8000',
                    'OCcolor':'#04B404', 'ChatLogSize':12, 'InfoLogSize':10}

class PYCG:

    def __init__(self, local_host):
        #Initialization
        self.Connection = {local_host:''} #default host
        self.data, self.recv = '' ,''
        self.import_settings()
        self.base = Tk()
        self.style = ttk.Style()
        self.style.theme_use(settings['Theme'])
        #Create a window
        self.base.iconbitmap(default='clienticon.ico')
        self.base.title('Py Chat 7')
        self.base.geometry("815x480")
        self.base.resizable(width=FALSE, height=FALSE)
        #Create the Chat window
        self.ChatLog = Text(self.base, bg="white", font=("Arial", settings['ChatLogSize']))
        self.ChatLog.config(state = DISABLED)
        #Bind a scrollbar to the Chat window
        self.Chat_bar = ttk.Scrollbar(self.base, command=self.ChatLog.yview, cursor="heart")
        self.ChatLog['yscrollcommand'] = self.Chat_bar.set
        #Create the box to enter message
        self.EntryBox = Text(self.base, bg="white", font="Arial")
        self.EntryBox.bind("<Return>", lambda event: self.EntryBox.config(state = DISABLED))
        self.EntryBox.bind("<KeyRelease-Return>", self.S_PressAction)
        #Create the Button to send message
        self.SendButton = ttk.Button(self.base, text="Send", width="7", command=self.S_ClickAction)
        #create the InfoLog
        self.InfoLog = Text(self.base, bg="white", font=("Arial", settings['InfoLogSize']))
        self.InfoLog.config(state = DISABLED)
        #Bind a scrollbar to the Info window
        self.Info_bar = ttk.Scrollbar(self.base, command=self.InfoLog.yview, cursor="pirate")
        self.InfoLog['yscrollcommand'] = self.Info_bar.set
        #Create the box to enter Command
        self.CommandBox = Text(self.base, bg="white", font="Arial")
        self.CommandBox.bind("<Return>", lambda event: self.CommandBox.config(state = DISABLED))
        self.CommandBox.bind("<KeyRelease-Return>", self.C_PressAction)
        #Create the Button to send Command
        self.CommandButton = ttk.Button(self.base, text="Run", width="7", command=self.C_ClickAction)
        #Menu
        self.menubar = Menu(self.base)
        self.base.config(menu = self.menubar)
        self.filemenu = Menu(self.menubar)
        self.filemenu.add_command(label = 'Close', command = quit)
        self.menubar.add_cascade(label= 'File', menu = self.filemenu)
        self.chatmenu = Menu(self.menubar)
        self.chatmenu.add_command(label = 'Clean', command = self.Clean)
        self.menubar.add_cascade(label= 'Chat', menu = self.chatmenu)
        self.connmenu = Menu(self.menubar)
        self.conn_menu()
        self.menubar.add_cascade(label= 'Connection', menu = self.connmenu)
        self.simbolimenu = Menu(self.menubar)
        for i in range(10):
            self.tendina(self.simbolimenu, Menu(self.simbolimenu), i)
        self.menubar.add_cascade(label= 'Symbols', menu = self.simbolimenu)
        #Place all components on the screen
        self.ChatLog.place(x=10,y=10, height=400, width=370)
        self.Chat_bar.place(x=380,y=10, height=400)
        self.SendButton.place(x=340, y=420, height=50, width=55)
        self.EntryBox.place(x=10, y=420, height=50, width=320)
        
        self.InfoLog.place(x=420,y=10, height=400, width=370)
        self.Info_bar.place(x=790,y=10, height=400)
        self.CommandButton.place(x=750, y=420, height=50, width=55)
        self.CommandBox.place(x=420, y=420, height=50, width=320)
        #Pop-up effect
        self.base.iconify()
        self.base.update()
        self.base.deiconify()

    def import_settings(self):
        '''fills settings dict with founded file settings'''
        try:
            file = open('Graphics_settings.txt', 'r')
            for line in file:
                line = line.split('=')
                if line[0] in settings:
                    settings[line[0]] = line[1] [:-1]
            file.close()
        except:
            pass

    def sim(self, s):
        '''Write s on the EntryBox'''
        self.EntryBox.insert(END, s)

    def button(self, frame, symbol):
        '''Crea un pulsante per il menu'''
        self.frame.add_command(label = symbol, command = lambda: self.sim(symbol))

    def tendina(self, simbolimenu, frame, o):
        '''Crea sotto-menu'''
        self.frame = Menu(self.simbolimenu)
        for i in Symbols[o] [1]:
            self.button(frame, i)
        self.simbolimenu.add_cascade(label = Symbols[o] [0], menu = self.frame)

    def connection(self, conn):
        '''update the menù'''
        self.connmenu.delete(1, END)
        self.Connection = conn
        self.conn_menu()

    def C_button(self, i):
        '''add a button'''
        self.connmenu.add_command(label = i, command = lambda: self.Connect(i))

    def conn_menu(self):
        '''create the menù'''
        for i in self.Connection:
            self.C_button(i)
        
    def Connect(self, name):
        '''selected partner'''
        self.recv = name
        self.LoadMyInfo('Now you are chatting with: '+name)

    def Clean(self):
        '''Clean-Screen'''
        self.ChatLog.config(state = NORMAL)
        self.ChatLog.delete("0.0", END)
        self.ChatLog.config(state = DISABLED)

    def S_PressAction(self, event):
        """Keyboard events"""
        self.EntryBox.config(state=NORMAL)
        self.S_ClickAction()
    
    def C_PressAction(self, event):
        """Keyboard events"""
        self.CommandBox.config(state=NORMAL)
        self.C_ClickAction()

    def S_ClickAction(self):
        """Mouse events"""
        #Write message to chat window
        self.EntryText = self.FilteredMessage(self.EntryBox.get("0.0",END))
        self.LoadMyEntry(self.EntryText) 
        self.ChatLog.yview(END) #Scroll to the bottom of chat windows
        self.EntryBox.delete("0.0",END) #Erase previous message in Entry Box
        if self.EntryText != '':
            self.data = self.recv+'&£&[DATA]&£&'+self.EntryText

    def C_ClickAction(self):
        """Mouse events"""
        #Write message to chat window
        self.EntryText = self.FilteredMessage(self.CommandBox.get("0.0",END))
        self.LoadMyInfo(self.EntryText) 
        self.InfoLog.yview(END) #Scroll to the bottom of chat windows
        self.CommandBox.delete("0.0",END) #Erase previous message in Entry Box
        if self.EntryText != '':
            self.data = self.recv+'&£&[COMMAND]&£&'+self.EntryText

    def idata(self):
        d = self.data
        self.data = ''
        return d

    def FilteredMessage(self, EntryText):
        """Filter out all useless white lines at the end of a 
        string, returns a new, beautifully filtered string."""
        if EntryText.isspace():
            return ''
        EndFiltered = ''        
        for i in range(len(EntryText)-1,-1,-1):
            if EntryText[i]!='\n':
                EndFiltered = EntryText[0:i+1]
                break
        for i in range(0,len(EndFiltered), 1):
                if EndFiltered[i] != "\n":
                        return EndFiltered[i:]#+'\n'
        return ''

    def LoadMyEntry(self, EntryText):
        '''Load my entry'''
        if EntryText != '':
            self.ChatLog.config(state = NORMAL)
            if self.ChatLog.index('end') != None:
                LineNumber = float(self.ChatLog.index('end')) - 1.0
                self.ChatLog.insert(END, "You: " + EntryText+'\n')
                self.ChatLog.tag_add("You", LineNumber, LineNumber + 0.4)
                self.ChatLog.tag_config("You", foreground = settings['MMcolor'], font = ("Arial", int(settings['ChatLogSize']), "bold"))
                self.ChatLog.config(state = DISABLED)
                self.ChatLog.yview(END)

    def LoadOtherEntry(self, EntryText):
        '''Load other entry'''
        if EntryText != '':
            self.ChatLog.config(state=NORMAL)
            if self.ChatLog.index('end') != None:
                LineNumber = float(self.ChatLog.index('end'))-1.0
                self.ChatLog.insert(END, 'Other: ' + EntryText+'\n')
                self.ChatLog.tag_add('Other: ', LineNumber, LineNumber+0.6)
                self.ChatLog.tag_config('Other: ', foreground=settings['OMcolor'], font=("Arial", int(settings['ChatLogSize']), "bold"))
                self.ChatLog.config(state=DISABLED)
                self.ChatLog.yview(END)

    def LoadOtherInfo(self, EntryText):
        '''Load an info with SERVER tag'''
        if EntryText != '':
            self.InfoLog.config(state = NORMAL)
            if self.InfoLog.index('end') != None:
                LineNumber = float(self.InfoLog.index('end')) - 1.0
                self.InfoLog.insert(END, "Server: " + EntryText+'\n')
                self.InfoLog.tag_add("Server", LineNumber, LineNumber + 0.7)
                self.InfoLog.tag_config("Server", foreground = settings['OCcolor'], font = ("Arial", int(settings['InfoLogSize']), "bold"))
                self.InfoLog.config(state = DISABLED)
                self.InfoLog.yview(END)

    def LoadMyInfo(self, EntryText):
        '''Load an info with SERVER tag'''
        if EntryText != '':
            self.InfoLog.config(state = NORMAL)
            if self.InfoLog.index('end') != None:
                LineNumber = float(self.InfoLog.index('end')) - 1.0
                self.InfoLog.insert(END, "Client: " + EntryText+'\n')
                self.InfoLog.tag_add("Client", LineNumber, LineNumber + 0.7)
                self.InfoLog.tag_config("Client", foreground = settings['MCcolor'], font = ("Arial", int(settings['InfoLogSize']), "bold"))
                self.InfoLog.config(state = DISABLED)
                self.InfoLog.yview(END)

    def M_loop(self):
        '''Mainloop'''
        self.base.mainloop()

if __name__ == '__main__':
    test = PYCG('Echo')
    test.LoadMyInfo('this is a command')
    test.LoadOtherInfo('Hello from Server')
    test.LoadMyEntry('this is my message')
    test.LoadOtherEntry('and this is the echo')
    test.M_loop()
