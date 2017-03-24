VERSION 5.00
Begin VB.Form frmOptions 
   BorderStyle     =   4  'Fixed ToolWindow
   Caption         =   " Options"
   ClientHeight    =   1830
   ClientLeft      =   45
   ClientTop       =   315
   ClientWidth     =   4680
   LinkTopic       =   "Form1"
   MaxButton       =   0   'False
   MinButton       =   0   'False
   ScaleHeight     =   1830
   ScaleWidth      =   4680
   StartUpPosition =   2  'CenterScreen
   Begin VB.CommandButton cmdBrowse2 
      Caption         =   "Browse"
      Height          =   375
      Left            =   3720
      TabIndex        =   6
      Top             =   720
      Width           =   855
   End
   Begin VB.CommandButton cmdBrowse1 
      Caption         =   "Browse"
      Height          =   375
      Left            =   3720
      TabIndex        =   5
      Top             =   240
      Width           =   855
   End
   Begin VB.CommandButton cmdSave 
      Caption         =   "Save"
      Height          =   375
      Left            =   3240
      TabIndex        =   4
      Top             =   1320
      Width           =   1215
   End
   Begin VB.TextBox txtTLinkPath 
      Height          =   375
      Left            =   1080
      TabIndex        =   3
      Top             =   720
      Width           =   2535
   End
   Begin VB.TextBox txtTASMPath 
      Height          =   375
      Left            =   1080
      TabIndex        =   2
      Top             =   240
      Width           =   2535
   End
   Begin VB.Label lblGeneral 
      AutoSize        =   -1  'True
      Caption         =   "TLink Path :"
      Height          =   195
      Index           =   1
      Left            =   120
      TabIndex        =   1
      Top             =   720
      Width           =   870
   End
   Begin VB.Label lblGeneral 
      AutoSize        =   -1  'True
      Caption         =   "TASM Path :"
      Height          =   195
      Index           =   0
      Left            =   120
      TabIndex        =   0
      Top             =   240
      Width           =   915
   End
End
Attribute VB_Name = "frmOptions"
Attribute VB_GlobalNameSpace = False
Attribute VB_Creatable = False
Attribute VB_PredeclaredId = True
Attribute VB_Exposed = False
Option Explicit

Private Sub cmdBrowse1_Click()
    Dim sFile As String


    With frmMain.dlgCommonDialog
        .DialogTitle = "TASM Compiler"
        .CancelError = False
        'ToDo: set the flags and attributes of the common dialog control
        .Filter = "TASM.EXE|TASM.EXE"
        .ShowOpen
        If Len(.FileName) = 0 Then
            Exit Sub
        End If
        sFile = .FileName
    End With
    txtTASMPath.Text = sFile
End Sub

Private Sub cmdBrowse2_Click()
    Dim sFile As String


    With frmMain.dlgCommonDialog
        .DialogTitle = "Linker"
        .CancelError = False
        'ToDo: set the flags and attributes of the common dialog control
        .Filter = "TLINK.EXE|TLINK.EXE"
        .ShowOpen
        If Len(.FileName) = 0 Then
            Exit Sub
        End If
        sFile = .FileName
    End With
    txtTLinkPath.Text = sFile
End Sub

Private Sub cmdSave_Click()
Dim FileNum
FileNum = FreeFile
Open App.Path + "\Settings.txt" For Output As FileNum
Print #FileNum, GetShortPath(txtTASMPath.Text)
Print #FileNum, GetShortPath(txtTLinkPath.Text)
Close FileNum
MsgBox "Settings Saved. Please Restart TASMEditor.", vbInformation
End
End Sub

