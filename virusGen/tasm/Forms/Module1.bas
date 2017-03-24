Attribute VB_Name = "modGeneral"
Option Explicit

Public fMainForm As frmMain
Public TASMPath As String
Public TLinkPath As String
Public ShortAppPath As String
Public Type POINTAPI
    x As Long
    y As Long
End Type
Public Type RECT
    Left As Long
    Top As Long
    Right As Long
    Bottom As Long
End Type
Public Const DT_CALCRECT = &H400
Public Const EM_LINEFROMCHAR = &HC9
Public Const EM_LINEINDEX = &HBB
Public Const EM_LINELENGTH = &HC1
Public Const EM_GETLINECOUNT = &HBA
Public Const EM_GETFIRSTVISIBLELINE = &HCE
Public Const SFF_SELECTION = &H8000&
Public Const WM_USER = &H400

Public Const EM_EXSETSEL = (WM_USER + 55)
Public Const EM_EXGETSEL = (WM_USER + 52)
Public Const EM_POSFROMCHAR = &HD6&
Public Const EM_CHARFROMPOS = &HD7&
Public Const EM_EXLINEFROMCHAR = (WM_USER + 54)
Public Const EM_GETTEXTRANGE = (WM_USER + 75)
Public Const EM_STREAMIN = (WM_USER + 73)

Public Const PS_SOLID = 0

Public Const DT_RIGHT = &H2
Public Const DT_VCENTER = &H4
Public Const DT_SINGLELINE = &H20

Public Const EM_HIDESELECTION = WM_USER + 63

Public Const GWL_WNDPROC = (-4)
Private Const WM_VSCROLL = &H115
Public Declare Function GetCaretPos Lib "user32" (lpPoint As POINTAPI) As Long
Public Declare Function GetShortPathName Lib "kernel32" Alias "GetShortPathNameA" (ByVal lpszLongPath As String, ByVal lpszShortPath As String, ByVal cchBuffer As Long) As Long
Public Declare Function GetTickCount Lib "kernel32" () As Long
Public Declare Function DrawText Lib "user32" Alias "DrawTextA" (ByVal hdc As Long, ByVal lpStr As String, ByVal nCount As Long, lpRect As RECT, ByVal wFormat As Long) As Long
Public Declare Function SendMessageByRef Lib "user32" Alias "SendMessageA" (ByVal hwnd As Long, ByVal wMsg As Long, wParam As Long, lParam As Any) As Long
Public Declare Function SendMessageByLong Lib "user32" Alias "SendMessageA" (ByVal hwnd As Long, ByVal wMsg As Long, ByVal wParam As Long, ByVal lParam As Long) As Long
Public Declare Function SendMessageLong Lib "user32" Alias _
        "SendMessageA" (ByVal hwnd As Long, ByVal wMsg As Long, _
        ByVal wParam As Long, lParam As Long) As Long
Public Declare Function GetClientRect Lib "user32" (ByVal hwnd As Long, lpRect As RECT) As Long
Public Declare Function CreateSolidBrush Lib "gdi32" (ByVal crColor As Long) As Long
Public Declare Function SendMessage Lib "user32" Alias "SendMessageA" (ByVal hwnd As Long, ByVal wMsg As Long, ByVal wParam As Long, lParam As Long) As Long
Public Declare Function SetWindowLong Lib "user32" Alias "SetWindowLongA" (ByVal hwnd As Long, ByVal nIndex As Long, ByVal dwNewLong As Long) As Long
Public Declare Function CallWindowProc Lib "user32" Alias "CallWindowProcA" (ByVal lpPrevWndFunc As Long, ByVal hwnd As Long, ByVal Msg As Long, ByVal wParam As Long, ByVal lParam As Long) As Long

Public Declare Function OffsetRect Lib "user32" (lpRect As RECT, ByVal x As Long, ByVal y As Long) As Long
Public Declare Function FillRect Lib "user32" (ByVal hdc As Long, lpRect As RECT, ByVal hBrush As Long) As Long
Public Declare Function OleTranslateColor Lib "oleaut32.dll" (ByVal lOleColor As Long, ByVal lHPalette As Long, lColorRef As Long) As Long

Public Declare Function DeleteObject Lib "gdi32" (ByVal hObject As Long) As Long
Public Declare Function SetTextColor Lib "gdi32" (ByVal hdc As Long, ByVal crColor As Long) As Long

Public Declare Function MoveToEx Lib "gdi32" (ByVal hdc As Long, ByVal x As Long, ByVal y As Long, lpPoint As POINTAPI) As Long
Public Declare Function LineTo Lib "gdi32" (ByVal hdc As Long, ByVal x As Long, ByVal y As Long) As Long
Public Declare Function CreatePen Lib "gdi32" (ByVal nPenStyle As Long, ByVal nWidth As Long, ByVal crColor As Long) As Long
Public Declare Function SelectObject Lib "gdi32" (ByVal hdc As Long, ByVal hObject As Long) As Long
Public Declare Function SetCaretPos Lib "user32" (ByVal x As Integer, ByVal y As Integer) As Integer

Public Function GetShortPath(strFileName As String) As String
Dim lAns As Long
Dim sAns As String
Dim iLen As Integer
   
On Error Resume Next
'this function doesn't work if the file doesn't exist
If Dir(strFileName) = "" Then
    GetShortPath = strFileName
    Exit Function
End If
sAns = Space(255)
lAns = GetShortPathName(strFileName, sAns, 255)
GetShortPath = Left(sAns, lAns)
If GetShortPath = "" Then GetShortPath = strFileName
End Function
Sub Main()
    ShortAppPath = GetShortPath(App.Path + "\Help.txt")
    ShortAppPath = Left$(ShortAppPath, Len(ShortAppPath) - 9)
    TASMPath = GetShortPath(App.Path + "\TASM\Tasm.exe")
    TLinkPath = GetShortPath(App.Path + "\TASM\tlink.exe")
    frmMain.Show
End Sub

Public Function GetLine(TB As RichTextBox) As String
    Dim LineArr
    Dim TmpStr As String
    TmpStr = Left$(TB.Text, TB.SelStart)
    LineArr = Split(TmpStr, vbCrLf)
    GetLine = LineArr(UBound(LineArr))
    
End Function
Public Function GetWordFromLeft(sText As String, StopChar As String) As String
    Dim Pos As String
    Pos = InStr(1, sText, StopChar, vbTextCompare)
    GetWordFromLeft = Left$(sText, Pos)
End Function

Public Sub PauseFor(Delay As Long)
    Dim Count1 As Long
    Dim Count2 As Long
    Count1 = GetTickCount()
    Count2 = GetTickCount()
    While ((Count2 - Count1) < Delay)
        DoEvents
        Count2 = GetTickCount()
    Wend
End Sub

Public Function TranslateColor(ByVal clr As OLE_COLOR, Optional hPal As Long = 0) As Long
    If OleTranslateColor(clr, hPal, TranslateColor) Then
        TranslateColor = -1
    End If
End Function

Public Function LineCount() As Long
    LineCount = SendMessageByRef(frmMain.txtCode.hwnd, EM_GETLINECOUNT, 0&, 0&)
End Function

Public Function LineForCharacterIndex(lIndex As Long) As Long
    LineForCharacterIndex = SendMessageByLong(frmMain.txtCode.hwnd, EM_LINEFROMCHAR, lIndex, 0)
End Function

Public Function FirstVisibleLine() As Long
    FirstVisibleLine = SendMessageByLong(frmMain.txtCode.hwnd, EM_GETFIRSTVISIBLELINE, 0, 0)
End Function
Public Sub DrawLines(picTo As PictureBox)
    Dim lLine As Long
    Dim lCount As Long
    Dim lCurrent As Long
    Dim hBr As Long
    Dim lEnd As Long
    Dim lhDC As Long
    Dim bComplete As Boolean
    Dim tr As RECT, tTR As RECT
    Dim oCol As OLE_COLOR
    Dim lStart As Long
    Dim lEndLine As Long
    Dim tPO As POINTAPI
    Dim lLineHeight As Long
    Dim hPen As Long
    Dim hPenOld As Long

    'Debug.Print "DrawLines"
    lhDC = picTo.hdc
    DrawText lhDC, "Hy", 2, tTR, DT_CALCRECT
    lLineHeight = tTR.Bottom - tTR.Top

    lCount = LineCount
    lCurrent = SendMessageLong(frmMain.txtCode.hwnd, EM_LINEFROMCHAR, frmMain.txtCode.SelStart, 0&)
    lStart = frmMain.txtCode.SelStart
    lEnd = frmMain.txtCode.SelStart + frmMain.txtCode.SelLength - 1
    If (lEnd > lStart) Then
        lEndLine = LineForCharacterIndex(lEnd)
    Else
        lEndLine = lCurrent
    End If
    lLine = FirstVisibleLine
    GetClientRect picTo.hwnd, tr
    lEnd = tr.Bottom - tr.Top

    hBr = CreateSolidBrush(TranslateColor(picTo.BackColor))
    FillRect lhDC, tr, hBr
    DeleteObject hBr
    tr.Left = 2
    tr.Right = tr.Right - 2
    tr.Top = 0
    tr.Bottom = tr.Top + lLineHeight

    SetTextColor lhDC, TranslateColor(vbButtonShadow)

    Do
        ' Ensure correct colour:
        If (lLine = lCurrent) Then
            SetTextColor lhDC, TranslateColor(vbWindowText)
        ElseIf (lLine = lEndLine + 1) Then
            SetTextColor lhDC, TranslateColor(vbButtonShadow)
        End If
        ' Draw the line number:
        DrawText lhDC, CStr(lLine + 1), -1, tr, DT_RIGHT

        ' Increment the line:
        lLine = lLine + 1
        ' Increment the position:
        OffsetRect tr, 0, lLineHeight
        If (tr.Bottom > lEnd) Or (lLine + 1 > lCount) Then
            bComplete = True
        End If
    Loop While Not bComplete

    ' Draw a line...
    MoveToEx lhDC, tr.Right + 1, 0, tPO
    hPen = CreatePen(PS_SOLID, 1, TranslateColor(vbButtonShadow))
    hPenOld = SelectObject(lhDC, hPen)
    LineTo lhDC, tr.Right + 1, lEnd
    SelectObject lhDC, hPenOld
    DeleteObject hPen
    If picTo.AutoRedraw Then
        picTo.Refresh
    End If

End Sub
