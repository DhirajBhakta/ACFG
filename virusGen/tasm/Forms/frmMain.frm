VERSION 5.00
Object = "{F9043C88-F6F2-101A-A3C9-08002B2F49FB}#1.2#0"; "comdlg32.ocx"
Object = "{831FDD16-0C5C-11D2-A9FC-0000F8754DA1}#2.0#0"; "MSCOMCTL.OCX"
Object = "{3B7C8863-D78F-101B-B9B5-04021C009402}#1.2#0"; "RICHTX32.OCX"
Begin VB.Form frmMain 
   Appearance      =   0  'Flat
   Caption         =   "TASMEditor"
   ClientHeight    =   3090
   ClientLeft      =   165
   ClientTop       =   855
   ClientWidth     =   4680
   Icon            =   "frmMain.frx":0000
   LinkTopic       =   "Form1"
   ScaleHeight     =   546
   ScaleMode       =   3  'Pixel
   ScaleWidth      =   792
   StartUpPosition =   3  'Windows Default
   Begin VB.PictureBox picLines 
      Appearance      =   0  'Flat
      BorderStyle     =   0  'None
      BeginProperty Font 
         Name            =   "Courier New"
         Size            =   9.75
         Charset         =   0
         Weight          =   700
         Underline       =   0   'False
         Italic          =   0   'False
         Strikethrough   =   0   'False
      EndProperty
      ForeColor       =   &H80000008&
      Height          =   6795
      Left            =   0
      ScaleHeight     =   6795
      ScaleWidth      =   375
      TabIndex        =   5
      TabStop         =   0   'False
      Top             =   600
      Width           =   375
   End
   Begin MSComctlLib.ListView lstLog 
      Height          =   1575
      Left            =   390
      TabIndex        =   4
      TabStop         =   0   'False
      Top             =   4440
      Width           =   4575
      _ExtentX        =   8070
      _ExtentY        =   2778
      View            =   3
      LabelEdit       =   1
      LabelWrap       =   -1  'True
      HideSelection   =   -1  'True
      FullRowSelect   =   -1  'True
      HotTracking     =   -1  'True
      HoverSelection  =   -1  'True
      _Version        =   393217
      ForeColor       =   -2147483640
      BackColor       =   12648447
      BorderStyle     =   1
      Appearance      =   0
      NumItems        =   2
      BeginProperty ColumnHeader(1) {BDD1F052-858B-11D1-B16A-00C0F0283628} 
         Text            =   "Error Descriptioin"
         Object.Width           =   38100
      EndProperty
      BeginProperty ColumnHeader(2) {BDD1F052-858B-11D1-B16A-00C0F0283628} 
         SubItemIndex    =   1
         Text            =   "Line Number"
         Object.Width           =   38100
      EndProperty
   End
   Begin RichTextLib.RichTextBox txtHelp 
      Height          =   495
      Left            =   1920
      TabIndex        =   3
      TabStop         =   0   'False
      Top             =   1440
      Visible         =   0   'False
      Width           =   4575
      _ExtentX        =   8070
      _ExtentY        =   873
      _Version        =   393217
      BackColor       =   8454143
      Appearance      =   0
      TextRTF         =   $"frmMain.frx":0442
      BeginProperty Font {0BE35203-8F91-11CE-9DE3-00AA004BB851} 
         Name            =   "Arial"
         Size            =   8.25
         Charset         =   0
         Weight          =   400
         Underline       =   0   'False
         Italic          =   0   'False
         Strikethrough   =   0   'False
      EndProperty
   End
   Begin RichTextLib.RichTextBox txtCode 
      Height          =   3855
      Left            =   390
      TabIndex        =   2
      Top             =   600
      Width           =   11775
      _ExtentX        =   20770
      _ExtentY        =   6800
      _Version        =   393217
      BackColor       =   16777215
      Enabled         =   -1  'True
      ScrollBars      =   2
      Appearance      =   0
      AutoVerbMenu    =   -1  'True
      TextRTF         =   $"frmMain.frx":04B9
      BeginProperty Font {0BE35203-8F91-11CE-9DE3-00AA004BB851} 
         Name            =   "Courier New"
         Size            =   9.75
         Charset         =   0
         Weight          =   400
         Underline       =   0   'False
         Italic          =   0   'False
         Strikethrough   =   0   'False
      EndProperty
   End
   Begin MSComDlg.CommonDialog dlgCommonDialog 
      Left            =   1740
      Top             =   1305
      _ExtentX        =   847
      _ExtentY        =   847
      _Version        =   393216
   End
   Begin MSComctlLib.StatusBar sbStatusBar 
      Align           =   2  'Align Bottom
      Height          =   270
      Left            =   0
      TabIndex        =   0
      Top             =   7920
      Width           =   11880
      _ExtentX        =   20955
      _ExtentY        =   476
      _Version        =   393216
      BeginProperty Panels {8E3867A5-8586-11D1-B16A-00C0F0283628} 
         NumPanels       =   3
         BeginProperty Panel1 {8E3867AB-8586-11D1-B16A-00C0F0283628} 
            AutoSize        =   1
            Object.Width           =   15293
            Text            =   "Status"
            TextSave        =   "Status"
         EndProperty
         BeginProperty Panel2 {8E3867AB-8586-11D1-B16A-00C0F0283628} 
            Style           =   6
            AutoSize        =   2
            TextSave        =   "8/30/2003"
         EndProperty
         BeginProperty Panel3 {8E3867AB-8586-11D1-B16A-00C0F0283628} 
            Style           =   5
            AutoSize        =   2
            TextSave        =   "6:37 PM"
         EndProperty
      EndProperty
   End
   Begin MSComctlLib.ImageList imlToolbarIcons 
      Left            =   1740
      Top             =   1305
      _ExtentX        =   1005
      _ExtentY        =   1005
      BackColor       =   -2147483643
      ImageWidth      =   16
      ImageHeight     =   16
      MaskColor       =   12632256
      _Version        =   393216
      BeginProperty Images {2C247F25-8591-11D1-B16A-00C0F0283628} 
         NumListImages   =   12
         BeginProperty ListImage1 {2C247F27-8591-11D1-B16A-00C0F0283628} 
            Picture         =   "frmMain.frx":0539
            Key             =   "New"
         EndProperty
         BeginProperty ListImage2 {2C247F27-8591-11D1-B16A-00C0F0283628} 
            Picture         =   "frmMain.frx":064B
            Key             =   "Open"
         EndProperty
         BeginProperty ListImage3 {2C247F27-8591-11D1-B16A-00C0F0283628} 
            Picture         =   "frmMain.frx":075D
            Key             =   "Save"
         EndProperty
         BeginProperty ListImage4 {2C247F27-8591-11D1-B16A-00C0F0283628} 
            Picture         =   "frmMain.frx":086F
            Key             =   "Cut"
         EndProperty
         BeginProperty ListImage5 {2C247F27-8591-11D1-B16A-00C0F0283628} 
            Picture         =   "frmMain.frx":0981
            Key             =   "Copy"
         EndProperty
         BeginProperty ListImage6 {2C247F27-8591-11D1-B16A-00C0F0283628} 
            Picture         =   "frmMain.frx":0A93
            Key             =   "Paste"
         EndProperty
         BeginProperty ListImage7 {2C247F27-8591-11D1-B16A-00C0F0283628} 
            Picture         =   "frmMain.frx":0BA5
            Key             =   "Bold"
         EndProperty
         BeginProperty ListImage8 {2C247F27-8591-11D1-B16A-00C0F0283628} 
            Picture         =   "frmMain.frx":0CB7
            Key             =   "Italic"
         EndProperty
         BeginProperty ListImage9 {2C247F27-8591-11D1-B16A-00C0F0283628} 
            Picture         =   "frmMain.frx":0DC9
            Key             =   "Underline"
         EndProperty
         BeginProperty ListImage10 {2C247F27-8591-11D1-B16A-00C0F0283628} 
            Picture         =   "frmMain.frx":0EDB
            Key             =   "Align Left"
         EndProperty
         BeginProperty ListImage11 {2C247F27-8591-11D1-B16A-00C0F0283628} 
            Picture         =   "frmMain.frx":0FED
            Key             =   "Center"
         EndProperty
         BeginProperty ListImage12 {2C247F27-8591-11D1-B16A-00C0F0283628} 
            Picture         =   "frmMain.frx":10FF
            Key             =   "Align Right"
         EndProperty
      EndProperty
   End
   Begin MSComctlLib.Toolbar tbToolBar 
      Align           =   1  'Align Top
      Height          =   420
      Left            =   0
      TabIndex        =   1
      Top             =   0
      Width           =   11880
      _ExtentX        =   20955
      _ExtentY        =   741
      ButtonWidth     =   609
      ButtonHeight    =   582
      Appearance      =   1
      ImageList       =   "imlToolbarIcons"
      _Version        =   393216
      BeginProperty Buttons {66833FE8-8583-11D1-B16A-00C0F0283628} 
         NumButtons      =   7
         BeginProperty Button1 {66833FEA-8583-11D1-B16A-00C0F0283628} 
            Key             =   "New"
            Object.ToolTipText     =   "New"
            ImageKey        =   "New"
         EndProperty
         BeginProperty Button2 {66833FEA-8583-11D1-B16A-00C0F0283628} 
            Key             =   "Open"
            Object.ToolTipText     =   "Open"
            ImageKey        =   "Open"
         EndProperty
         BeginProperty Button3 {66833FEA-8583-11D1-B16A-00C0F0283628} 
            Key             =   "Save"
            Object.ToolTipText     =   "Save"
            ImageKey        =   "Save"
         EndProperty
         BeginProperty Button4 {66833FEA-8583-11D1-B16A-00C0F0283628} 
            Style           =   3
         EndProperty
         BeginProperty Button5 {66833FEA-8583-11D1-B16A-00C0F0283628} 
            Key             =   "Cut"
            Object.ToolTipText     =   "Cut"
            ImageKey        =   "Cut"
         EndProperty
         BeginProperty Button6 {66833FEA-8583-11D1-B16A-00C0F0283628} 
            Key             =   "Copy"
            Object.ToolTipText     =   "Copy"
            ImageKey        =   "Copy"
         EndProperty
         BeginProperty Button7 {66833FEA-8583-11D1-B16A-00C0F0283628} 
            Key             =   "Paste"
            Object.ToolTipText     =   "Paste"
            ImageKey        =   "Paste"
         EndProperty
      EndProperty
   End
   Begin VB.Menu mnuFile 
      Caption         =   "&File"
      Begin VB.Menu mnuFileNew 
         Caption         =   "&New"
         Shortcut        =   ^N
      End
      Begin VB.Menu mnuFileOpen 
         Caption         =   "&Open..."
      End
      Begin VB.Menu mnuFileBar3 
         Caption         =   "-"
      End
      Begin VB.Menu mnuFileCompile 
         Caption         =   "Compile and Run"
         Shortcut        =   {F5}
      End
      Begin VB.Menu mnuFileBar0 
         Caption         =   "-"
      End
      Begin VB.Menu mnuFileSave 
         Caption         =   "&Save"
      End
      Begin VB.Menu mnuFileSaveAs 
         Caption         =   "Save &As..."
      End
      Begin VB.Menu mnuFileBar1 
         Caption         =   "-"
      End
      Begin VB.Menu mnuFileMRU 
         Caption         =   ""
         Index           =   1
         Visible         =   0   'False
      End
      Begin VB.Menu mnuFileMRU 
         Caption         =   ""
         Index           =   2
         Visible         =   0   'False
      End
      Begin VB.Menu mnuFileMRU 
         Caption         =   ""
         Index           =   3
         Visible         =   0   'False
      End
      Begin VB.Menu mnuFileBar2 
         Caption         =   "-"
         Visible         =   0   'False
      End
      Begin VB.Menu mnuFileExit 
         Caption         =   "E&xit"
      End
   End
   Begin VB.Menu mnuEdit 
      Caption         =   "&Edit"
      Begin VB.Menu mnuEditUndo 
         Caption         =   "&Undo"
      End
      Begin VB.Menu mnuEditBar0 
         Caption         =   "-"
      End
      Begin VB.Menu mnuEditCut 
         Caption         =   "Cu&t"
      End
      Begin VB.Menu mnuEditCopy 
         Caption         =   "&Copy"
      End
      Begin VB.Menu mnuEditPaste 
         Caption         =   "&Paste"
      End
   End
   Begin VB.Menu mnuView 
      Caption         =   "&View"
      Begin VB.Menu mnuViewToolbar 
         Caption         =   "&Toolbar"
         Checked         =   -1  'True
      End
      Begin VB.Menu mnuViewStatusBar 
         Caption         =   "Status &Bar"
         Checked         =   -1  'True
      End
      Begin VB.Menu mnuViewBar0 
         Caption         =   "-"
         Visible         =   0   'False
      End
      Begin VB.Menu mnuViewOptions 
         Caption         =   "&Options..."
         Visible         =   0   'False
      End
   End
   Begin VB.Menu mnuHelp 
      Caption         =   "&Help"
      Begin VB.Menu mnuHelpAbout 
         Caption         =   "&About "
      End
   End
End
Attribute VB_Name = "frmMain"
Attribute VB_GlobalNameSpace = False
Attribute VB_Creatable = False
Attribute VB_PredeclaredId = True
Attribute VB_Exposed = False
Option Explicit
Dim cmd As Integer
Dim intr As String

Private Type KeyW
    KeyWord As String
    Description As String
    Syntax As String
End Type
Dim KeyList() As KeyW
Private Sub Status(Stat As String)
    sbStatusBar.Panels(1).Text = Stat
End Sub
Private Sub Form_Load()
    Me.Left = GetSetting(App.Title, "Settings", "MainLeft", 1000)
    Me.Top = GetSetting(App.Title, "Settings", "MainTop", 1000)
    Me.Width = GetSetting(App.Title, "Settings", "MainWidth", 6500)
    Me.Height = GetSetting(App.Title, "Settings", "MainHeight", 6500)
    LoadKeyWords
End Sub
Private Sub LoadKeyWords()
    Dim FileNum
    FileNum = FreeFile
    ReDim KeyList(0) As KeyW

    Open App.Path + "\Help.txt" For Input As FileNum
    While Not EOF(FileNum)
        ReDim Preserve KeyList(UBound(KeyList) + 1) As KeyW
        Line Input #FileNum, KeyList(UBound(KeyList)).KeyWord
        Line Input #FileNum, KeyList(UBound(KeyList)).Description
        Line Input #FileNum, KeyList(UBound(KeyList)).Syntax
    Wend
    Close FileNum
End Sub

Private Sub Form_Resize()
    On Error GoTo errh
    txtCode.Width = Me.ScaleWidth - 24 - picLines.Width
    txtCode.Height = (Me.ScaleHeight - sbStatusBar.Height - txtCode.Top) * 0.7
    picLines.Height = txtCode.Height
    lstLog.Move txtCode.Left, txtCode.Top + txtCode.Height + 12, txtCode.Width, ((Me.ScaleHeight - sbStatusBar.Height - txtCode.Top) * 0.3) - 24
    lstLog.ColumnHeaders(1).Width = (lstLog.Width * 0.8)
    lstLog.ColumnHeaders(2).Width = (lstLog.Width * 0.2)
errh:
    If Err.Number <> 0 Then Exit Sub
End Sub

Private Sub Form_Unload(Cancel As Integer)
    Dim i As Integer


    'close all sub forms
    For i = Forms.Count - 1 To 1 Step -1
        Unload Forms(i)
    Next
    If Me.WindowState <> vbMinimized Then
        SaveSetting App.Title, "Settings", "MainLeft", Me.Left
        SaveSetting App.Title, "Settings", "MainTop", Me.Top
        SaveSetting App.Title, "Settings", "MainWidth", Me.Width
        SaveSetting App.Title, "Settings", "MainHeight", Me.Height
    End If
End Sub
Private Function LoadLog() As Boolean
    Dim FileNum
    Dim sLine As String
    FileNum = FreeFile
    Screen.MousePointer = vbArrow
    Open ShortAppPath + "\tasmout.txt" For Input As FileNum
    While Not EOF(FileNum)
        Line Input #FileNum, sLine
        If Left$(sLine, 9) = "**Error**" Then
            AddToError (sLine)
        End If
    Wend
    If lstLog.ListItems.Count <> 0 Then
        ShowError (lstLog.ListItems.Item(1).SubItems(1))
    End If
    Close FileNum
    If lstLog.ListItems.Count = 0 Then
    LoadLog = True
    Else
    LoadLog = False
    End If
End Function
Private Sub ShowError(LineNum As Integer)
    Dim Count As Integer
    Dim Pos As Integer
    Dim PA As POINTAPI
    txtHelp.TextRTF = ""
    Pos = 0
    Count = 1
    While Count < LineNum
        Pos = InStr(Pos + 1, txtCode.Text, vbCrLf, vbTextCompare)
        Count = Count + 1
    Wend
    txtCode.SelStart = Pos + 1
    
    txtCode.SelLength = InStr(Pos + 1, txtCode.Text, vbCrLf, vbTextCompare) - Pos
    txtCode.SetFocus
    Call txtCode_KeyUp(13, 0)
    GetCaretPos PA
    txtHelp.Move PA.x + 50, PA.y + 50
    txtHelp.SelStart = 1
    txtHelp.SelBold = True
    txtHelp.SelColor = vbRed
    txtHelp.SelText = " ERROR : "
    txtHelp.SelColor = vbBlack
    txtHelp.SelBold = False
    txtHelp.SelText = lstLog.SelectedItem.Text
    txtHelp.Visible = True
    SetCaretPos 0, 0
End Sub
Private Sub AddToError(sLine As String)
    Dim Pos As Integer
    Dim LineNum As String
    Pos = InStr(1, sLine, "(", vbTextCompare)
    sLine = Right(sLine, Len(sLine) - Pos)
    Pos = InStr(1, sLine, ")", vbTextCompare)
    LineNum = Left$(sLine, Pos - 1)
    sLine = Trim(Right(sLine, Len(sLine) - Pos - 1))
    LineNum = Trim(LineNum)
    lstLog.ListItems.Add(, , sLine).SubItems(1) = LineNum
End Sub
Private Function LoadOutput() As String
    Dim FileNum
    Dim sLine As String
    Dim sLine2 As String
    Dim SingleChar As String
    FileNum = FreeFile
    Open ShortAppPath + "\appout.txt" For Input As FileNum
    While Not EOF(FileNum)
        Line Input #FileNum, sLine
        While Len(sLine) > 0
            SingleChar = Left$(sLine, 1)
            sLine = Right(sLine, Len(sLine) - 1)
            SingleChar = Asc(SingleChar)
            SingleChar = Hex(SingleChar) & " "
            sLine2 = sLine2 & SingleChar
        Wend
        sLine2 = sLine2 & vbCrLf
    Wend
    Close FileNum
    LoadOutput = sLine2
End Function

Private Sub lstLog_Click()
If lstLog.ListItems.Count > 1 Then
    txtCode.SetFocus
    txtCode.SelStart = 1
    ShowError (lstLog.SelectedItem.SubItems(1))
End If
End Sub

Private Sub mnuFileCompile_Click()
    On Error GoTo errh
    Dim Path As String
    Dim TmpPath As String
    Screen.MousePointer = vbHourglass
    lstLog.ListItems.Clear
    If Me.Caption = "TASMEditor" Then
        mnuFileSaveAs_Click
    Else
        mnuFileSave_Click
        Path = Right(Me.Caption, Len(Me.Caption) - 11)
        If Dir(ShortAppPath + "\tasmout.txt") <> "" Then Kill ShortAppPath + "\tasmout.txt"
        If Dir(ShortAppPath + "\tlink.txt") <> "" Then Kill ShortAppPath + "\tlink.txt"
        If Dir(ShortAppPath + "\appout.txt") <> "" Then Kill ShortAppPath + "\appout.txt"
        Status "Compiling..."
        Shell TASMPath & " " & Path & " > " & ShortAppPath + "\tasmout.txt", vbHide
        Status "Program Compiled."
        DoEvents
        PauseFor (2000)
        While (Dir(App.Path + "\tasmout.txt") = "")
            DoEvents
        Wend

        If LoadLog Then
            Status "Linking..."
            Shell TLinkPath & " " & Replace(Path, ".asm", ".obj", , , vbTextCompare) & " > " & ShortAppPath + "\tlink.txt", vbHide
            Status "Linking Done"
            DoEvents
            PauseFor (500)
            While (Dir(App.Path + "\tlink.txt") = "")
                DoEvents
            Wend
            Status "Running Executable"
            Shell Replace(Path, ".asm", ".exe", , , vbTextCompare) & " > " & ShortAppPath + "\appout.txt", vbHide
            Status "Generating Output"
            DoEvents
            PauseFor (1000)
            While (Dir(App.Path + "\appout.txt") = "")
                DoEvents
            Wend
            frmOutput.txtOutput.Text = LoadOutput
            Screen.MousePointer = vbArrow
            frmOutput.Show vbModal, Me
        Else
            Status "Compile Failed"
            Screen.MousePointer = vbArrow
        End If



    End If

errh:
    If Err.Number = 75 Then
        DoEvents
        Resume
    End If
End Sub

'Private Sub mnuViewOptions_Click()
'    Unload Me
'    frmOptions.Show
'End Sub

Private Sub tbToolBar_ButtonClick(ByVal Button As MSComctlLib.Button)
    On Error Resume Next
    Select Case Button.Key
        Case "New"
            'ToDo: Add 'New' button code.
            mnuFileNew_Click
        Case "Open"
            mnuFileOpen_Click
        Case "Save"
            mnuFileSave_Click
        Case "Cut"
            mnuEditCut_Click
        Case "Copy"
            mnuEditCopy_Click
        Case "Paste"
            mnuEditPaste_Click
    End Select
End Sub

Private Sub mnuHelpAbout_Click()
    frmAbout.Show vbModal, Me
End Sub



Private Sub mnuViewStatusBar_Click()
    mnuViewStatusBar.Checked = Not mnuViewStatusBar.Checked
    sbStatusBar.Visible = mnuViewStatusBar.Checked
End Sub

Private Sub mnuViewToolbar_Click()
    mnuViewToolbar.Checked = Not mnuViewToolbar.Checked
    tbToolBar.Visible = mnuViewToolbar.Checked
End Sub

Private Sub mnuEditPaste_Click()
    'ToDo: Add 'mnuEditPaste_Click' code.
    SendKeys "^v"
End Sub

Private Sub mnuEditCopy_Click()
    'ToDo: Add 'mnuEditCopy_Click' code.
    SendKeys "^c"
End Sub

Private Sub mnuEditCut_Click()
    'ToDo: Add 'mnuEditCut_Click' code.
    SendKeys "^x"
End Sub

Private Sub mnuEditUndo_Click()
    'ToDo: Add 'mnuEditUndo_Click' code.
    SendKeys "^z"
End Sub

Private Sub mnuFileExit_Click()
    'unload the form
    End

End Sub

Private Sub mnuFileSaveAs_Click()
    'ToDo: Add 'mnuFileSaveAs_Click' code.
    Dim sFile As String
    Dim Path As String

    With dlgCommonDialog
        .DialogTitle = "Save"
        .CancelError = False
        'ToDo: set the flags and attributes of the common dialog control
        .Filter = "TASM Files (*.ASM)|*.ASM"
        .ShowSave
        If Len(.FileName) = 0 Then
            Exit Sub
        End If
        sFile = .FileName
    End With
    Path = GetShortPath(sFile)
    Me.Caption = "TASMEditor-" & Path
    mnuFileSave_Click
End Sub

Private Sub mnuFileSave_Click()
    'ToDo: Add 'mnuFileSave_Click' code.
    Dim Path As String
    Dim FileNum

    If Me.Caption = "TASMEditor" Then
        mnuFileSaveAs_Click
    Else
        Path = GetShortPath(Right(Me.Caption, Len(Me.Caption) - 11))
        FileNum = FreeFile
        Open Path For Output As FileNum
        Print #FileNum, UCase(txtCode.Text)
        Close FileNum
    End If
End Sub

Private Sub mnuFileClose_Click()
    'ToDo: Add 'mnuFileClose_Click' code.
    MsgBox "Add 'mnuFileClose_Click' code."
End Sub

Private Sub mnuFileOpen_Click()
    Dim sFile As String


    With dlgCommonDialog
        .DialogTitle = "Open"
        .CancelError = False
        'ToDo: set the flags and attributes of the common dialog control
        .Filter = "TASM Files (*.ASM)|*.ASM"
        .ShowOpen
        If Len(.FileName) = 0 Then
            Exit Sub
        End If
        sFile = .FileName
    End With
    txtCode.LoadFile sFile, rtfText
    sFile = GetShortPath(sFile)
    Me.Caption = "TASMEditor-" & sFile
End Sub


Private Sub mnuFileNew_Click()
    txtCode.TextRTF = ""
    Me.Caption = "TASMEditor"
End Sub




Private Sub GiveHelp(sKeyWord As String)
    Dim x As Integer
    Dim PA As POINTAPI
    txtHelp.TextRTF = ""
    For x = 1 To UBound(KeyList)
        If KeyList(x).KeyWord = Trim(sKeyWord) Then
            GetCaretPos PA
            txtHelp.Move PA.x, PA.y + 65
            txtHelp.SelStart = 1
            txtHelp.SelBold = True
            txtHelp.SelText = "  " & KeyList(x).Syntax & vbNewLine
            txtHelp.SelBold = False
            txtHelp.SelItalic = True
            txtHelp.SelText = "  " & KeyList(x).Description
            txtHelp.SelItalic = False
            txtHelp.Visible = True
            Exit For
        End If
    Next

End Sub




Private Sub txtCode_Click()
    txtHelp.Visible = False
End Sub



Private Sub txtCode_KeyDown(KeyCode As Integer, Shift As Integer)
Dim LastLine As String
Dim sKeyWord As String
Dim LastSelStart
If KeyCode = 13 Then
    LastLine = GetLine(txtCode)
    LastSelStart = txtCode.SelStart
    txtCode.SelStart = txtCode.SelStart - Len(LastLine)
    txtCode.SelLength = Len(LastLine)
    txtCode.SelText = UCase(txtCode.SelText)
    txtCode.SelStart = LastSelStart
    If Left$(LastLine, 1) = vbTab Then
        txtCode.SelText = vbNewLine & vbTab
        KeyCode = 0
    End If
End If
End Sub

Private Sub txtCode_KeyUp(KeyCode As Integer, Shift As Integer)
    If (KeyCode = 13) Or (KeyCode = 37) Or (KeyCode = 38) Or (KeyCode = 39) Or (KeyCode = 40) Or (KeyCode = 8) Then
        txtHelp.Visible = False
        DrawLines picLines
    End If
    If KeyCode = 32 Then
        txtHelp.TextRTF = ""
        GiveHelp (UCase(GetWordFromLeft(GetLine(txtCode), " ")))
    End If
End Sub





Private Sub txtCode_LostFocus()
    txtHelp.Visible = False

End Sub


Private Sub txtCode_MouseDown(Button As Integer, Shift As Integer, x As Single, y As Single)
    DrawLines picLines
End Sub
