"""
Script tạo file PDF mẫu chuẩn bằng pyHanko PdfFileWriter.
"""
import io
from pyhanko.pdf_utils import writer, generic

# Tạo một PDF writer mới với cấu trúc chuẩn
pdf_writer = writer.PdfFileWriter(stream_xrefs=False, init_page_tree=True)

# Tạo page dictionary thủ công
media_box = generic.ArrayObject([
    generic.NumberObject(0), generic.NumberObject(0),
    generic.NumberObject(612), generic.NumberObject(792)
])
page_dict = generic.DictionaryObject({
    generic.pdf_name('/Type'): generic.pdf_name('/Page'),
    generic.pdf_name('/MediaBox'): media_box,
})

# Thêm trang vào document
pdf_writer.insert_page(generic.DictionaryObject(page_dict))

# Xuất ra file
with open('test_in.pdf', 'wb') as f:
    pdf_writer.write(f)

print("test_in.pdf generated (pyHanko standard format)")
