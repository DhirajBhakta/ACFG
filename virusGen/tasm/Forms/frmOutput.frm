VERSION 5.00
Begin VB.Form frmOutput 
   BorderStyle     =   4  'Fixed ToolWindow
   Caption         =   " Output"
   ClientHeight    =   2475
   ClientLeft      =   45
   ClientTop       =   315
   ClientWidth     =   2955
   LinkTopic       =   "Form1"
   MaxButton       =   0   'False
   MinButton       =   0   'False
   ScaleHeight     =   2475
   ScaleWidth      =   2955
   ShowInTaskbar   =   0   'False
   StartUpPosition =   2  'CenterScreen
   Begin VB.CommandButton cmdClose 
      Caption         =   "Close"
      Height          =   375
      Left            =   960
      TabIndex        =   1
      Top             =   2040
      Width           =   975
   End
   Begin VB.TextBox txtOutput 
      Appearance      =   0  'Flat
      Height          =   1815
      Left            =   120
      TabIndex        =   0
      Top             =   120
      Width           =   2655
   End
End
Attribute VB_Name = "frmOutput"
Attribute VB_GlobalNameSpace = False
Attribute VB_Creatable = False
Attribute VB_PredeclaredId = True
Attribute VB_Exposed = False
Option Explicit

Private Sub cmdClose_Click()
    Unload Me
End Sub
