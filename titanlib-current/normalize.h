/*
 *  $Header: /usr/home/svn/cvsroot/wt1/titax2/libtitax/normalize.h,v 1.5 2010-11-24 10:30:03 jinhee Exp $
 *
 *  $Name: not supported by cvs2svn $
 *  $Author: jinhee $
 *  $Revision: 1.5 $
 *  $State: Exp $
 *
 *  CVS History:
 *
 *  $Log: not supported by cvs2svn $
 *  Revision 1.1  2010/02/01 14:03:05  jinhee
 *  modifed files for squid update.
 *
 *  Revision 1.1.1.1  2008/07/23 11:03:36  sean
 *  Initial Titax code.
 *
 *  Revision 1.5.658.1  2006/07/19 13:19:18  jsutherland
 *  Merged bug 661 and 711 into 3.2.1.0 - This is the new group URL list feature
 *
 *  Revision 1.5.672.1  2006/07/11 15:27:21  dredpath
 *  Merge of bug661 and bug711 features of per user URL categories and group B/A lists.
 *
 *  Revision 1.5  2005/03/01 11:23:33  gbisset
 *  Bug No. 354 - Make squid dump core, handle keywords better and fix crash in ctree code
 *
 *  Revision 1.4  2005/01/24 10:41:08  cmacdonald
 *  Added spaces to list of characters that will be normalised
 *
 *  Revision 1.3  2003/11/03 13:13:31  gordon
 *  fix spaces in keywork matching and page and url thresholds
 *
 *  Revision 1.2  2002/05/08 08:15:04  gordon
 *  cleaned up allowed url characters
 *
 *  Revision 1.1  2002/04/30 13:37:33  gordon
 *  url content filtering
 *
 *
 */

#define NORMALIZE_MAX 49
#define NORMALIZE_SIZE NORMALIZE_MAX+1

#include <sys/types.h>

static u_char N[] = {
0,  /* 00    NUL */
0,  /* 01    SOH   */
0,  /* 02    STX   */
0,  /* 03    ETX   */
0,  /* 04    EOT   */
0,  /* 05    ENQ   */
0,  /* 06    ACK   */
0,  /* 07    BEL */
0,  /* 08    BS  */
0,  /* 09    HT  */
0,  /* 0A    LF  */
0,  /* 0B    VT  */
0,  /* 0C    FF  */
0,  /* 0D    CR  */
0,  /* 0E    SO    */
0,  /* 0F    SI    */
0,  /* 10    DLE   */
0,  /* 11    DC1   */
0,  /* 12    DC2   */
0,  /* 13    DC3   */
0,  /* 14    DC4   */
0,  /* 15    NAK   */
0,  /* 16    SYN   */
0,  /* 17    ETB   */
0,  /* 18    CAN   */
0,  /* 19    EM    */
0,  /* 1A    SUB   */
0,  /* 1B    ESC   */
0,  /* 1C    FS    */
0,  /* 1D    GS    */
0,  /* 1E    RS    */
0,  /* 1F    US    */
49, /* 20    SPACE */
1,  /* 21    !     */
0,  /* 22    "     */
0,  /* 23    #     */
2,  /* 24    $*/
3,  /* 25    %*/
0,  /* 26    &*/
4,  /* 27    '*/
5,  /* 28    (*/
6,  /* 29    )*/
7,  /* 2A    **/
8,  /* 2B    +*/
22, /* 2C    ,*/
9,   /* 2D    -*/
20,  /* 2E    .*/
0,   /* 2F    /*/
10,  /* 30    0*/
11,  /* 31    1*/
12,  /* 32    2*/
13,  /* 33    3*/
14,  /* 34    4*/
15,  /* 35    5*/
16,  /* 36    6*/
17,  /* 37    7*/
18,  /* 38    8*/
19,  /* 39    9*/
0,   /* 3A    :*/
0,   /* 3B    ;*/
0,   /* 3C    <*/
0,   /* 3D    =*/
0,   /* 3E    >*/
0,   /* 3F    ?*/
0,   /* 40    @*/
24,  /* 41    A*/
25,  /* 42    B*/
26,  /* 43    C*/
27,  /* 44    D*/
28,  /* 45    E*/
29,  /* 46    F*/
30,  /* 47    G*/
31,  /* 48    H*/
32,  /* 49    I*/
33,  /* 4A    J*/
34,  /* 4B    K*/
35,  /* 4C    L*/
36,  /* 4D    M*/
37,  /* 4E    N*/
38,  /* 4F    O*/
39,  /* 50    P*/
40,  /* 51    Q*/
41,  /* 52    R*/
42,  /* 53    S*/
43,  /* 54    T*/
44,  /* 55    U*/
45,  /* 56    V*/
46,  /* 57    W*/
47,  /* 58    X*/
48,  /* 59    Y*/
23,  /* 5A    Z*/
0,   /* 5B    [*/
0,   /* 5C    \*/
0,   /* 5D    ]*/
0,   /* 5E    ^*/
21,  /* 5F    _*/
0,   /* 60    `*/
24,  /* 61    a*/
25,  /* 62    b*/
26,  /* 63    c*/
27,  /* 64    d  */
28,  /* 65    e  */
29,  /* 66    f  */
30,  /* 67    g  */
31,  /* 68    h  */
32,  /* 69    i  */
33,  /* 6A    j  */
34,  /* 6B    k  */
35,  /* 6C    l  */
36,  /* 6D    m  */
37,  /* 6E    n  */
38,  /* 6F    o  */
39,  /* 70    p  */
40,  /* 71    q  */
41,  /* 72    r  */
42,  /* 73    s  */
43,  /* 74    t  */
44,  /* 75    u  */
45,  /* 76    v  */
46,  /* 77    w  */
47,  /* 78    x  */
48,  /* 79    y  */
23,  /* 7A    z  */
0,  /* 7B    {  */
0,  /* 7C    |  */
0,  /* 7D    }  */
0,  /* 7E    ~  */
0,  /* 7F    DEL*/
0,  /* 80*/
0,  /* 81*/
0,  /* 82*/
0,  /* 83*/
0,  /* 84*/
0,  /* 85*/
0,  /* 86*/
0,  /* 87*/
0,  /* 88*/
0,  /* 89*/
0,  /* 8A*/
0,  /* 8B*/
0,  /* 8C*/
0,  /* 8D*/
0,  /* 8E*/
0,  /* 8F*/
0,  /* 90*/
0,  /* 91*/
0,  /* 92*/
0,  /* 93*/
0,  /* 94*/
0,  /* 95*/
0,  /* 96*/
0,  /* 97*/
0,  /* 98*/
0,  /* 99*/
0,  /* 9A*/
0,  /* 9B*/
0,  /* 9C*/
0,  /* 9D*/
0,  /* 9E*/
0,  /* 9F*/
0,  /* A0*/
0,  /* A1*/
0,  /* A2*/
0,  /* A3*/
0,  /* A4*/
0,  /* A5*/
0,  /* A6*/
0,  /* A7*/
0,  /* A8*/
0,  /* A9*/
0,  /* AA*/
0,  /* AB*/
0,  /* AC*/
0,  /* AD*/
0,  /* AE*/
0,  /* AF*/
0,  /* B0*/
0,  /* B1*/
0,  /* B2*/
0,  /* B3*/
0,  /* B4*/
0,  /* B5*/
0,  /* B6*/
0,  /* B7*/
0,  /* B8*/
0,  /* B9*/
0,  /* BA*/
0,  /* BB*/
0,  /* BC*/
0,  /* BD*/
0,  /* BE*/
0,  /* BF*/
0,  /* C0*/
0,  /* C1*/
0,  /* C2*/
0,  /* C3*/
0,  /* C4*/
0,  /* C5*/
0,  /* C6*/
0,  /* C7*/
0,  /* C8*/
0,  /* C9*/
0,  /* CA*/
0,  /* CB*/
0,  /* CC*/
0,  /* CD*/
0,  /* CE*/
0,  /* CF*/
0,  /* D0*/
0,  /* D1*/
0,  /* D2*/
0,  /* D3*/
0,  /* D4*/
0,  /* D5*/
0,  /* D6*/
0,  /* D7*/
0,  /* D8*/
0,  /* D9*/
0,  /* DA*/
0,  /* DB*/
0,  /* DC*/
0,  /* DD*/
0,  /* DE*/
0,  /* DF*/
0,  /* E0*/
0,  /* E1*/
0,  /* E2*/
0,  /* E3*/
0,  /* E4*/
0,  /* E5*/
0,  /* E6*/
0,  /* E7*/
0,  /* E8*/
0,  /* E9*/
0,  /* EA*/
0,  /* EB*/
0,  /* EC*/
0,  /* ED*/
0,  /* EE*/
0,  /* EF*/
0,  /* F0*/
0,  /* F1*/
0,  /* F2*/
0,  /* F3*/
0,  /* F4*/
0,  /* F5*/
0,  /* F6*/
0,  /* F7*/
0,  /* F8*/
0,  /* F9*/
0,  /* FA*/
0,  /* FB*/
0,  /* FC*/
0,  /* FD*/
0,  /* FE*/
0,  /* FF*/
};
