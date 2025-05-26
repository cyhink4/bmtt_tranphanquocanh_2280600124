from SinhVien import SinhVien


class QuanLySinhVien:
    def __init__(self):
        self.listSinhVien = []

    def generateID(self):
        max_id = 1
        if self.soLuongSinhVien() > 0:
            for sv in self.listSinhVien:
                if max_id < sv._id:
                    max_id = sv._id
        return max_id + 1

    def soLuongSinhVien(self):
        return len(self.listSinhVien)

    def nhapSinhVien(self):
        sv_id = self.generateID()
        name = input("Nhập tên sinh viên: ")
        sex = input("Nhập giới tính sinh viên: ")
        major =input("Nhập chuyên ngành của sinh viên: ")
        diem_tb = float(input("Nhập điểm của sinh viên: "))
        sv = SinhVien(sv_id, name, sex, major, diem_tb)
        self.xepLoaiHocLuc(sv)
        self.listSinhVien.append(sv)

    def updateSinhVien(self, ID):
        sv: SinhVien = self.findByID(ID)
        if sv is not None:
            name = input("Nhập tên sinh viên: ")
            sex = input("Nhập giới tính sinh viên: ")
            major = input("Nhập chuyên ngành của sinh viên: ")
            diem_tb = float(input("Nhập điểm của sinh viên: "))
            sv._name = name
            sv._sex = sex
            sv._major = major
            sv._diemTB = diem_tb
            self.xepLoaiHocLuc(sv)
        else:
            print(f"Sinh viên có ID = {ID} không tồn tại.")

    def sortByID(self):
        self.listSinhVien.sort(key=lambda x: x._id, reverse=False)

    def sortByName(self):
        self.listSinhVien.sort(key=lambda x: x._name, reverse=False)

    def sortByDiemTB(self):
        self.listSinhVien.sort(key=lambda x: x._diemTB, reverse=False)

    def findByID(self, ID):
        search_result = None
        if self.soLuongSinhVien() > 0:
            for sv in self.listSinhVien:
                if sv._id == ID:
                    search_result = sv
                    break
        return search_result

    def findByName(self, keyword):
        list_sv = []
        if self.soLuongSinhVien() > 0:
            for sv in self.listSinhVien:
                if keyword.upper() in sv._name.upper():
                    list_sv.append(sv)
        return list_sv

    def deleteByID(self, ID):
        is_deleted = False
        sv = self.findByID(ID)
        if sv is not None:
            self.listSinhVien.remove(sv)
            is_deleted = True
        return is_deleted

    def xepLoaiHocLuc(self, sv: SinhVien):
        if sv._diemTB >= 8:
            sv._hocLuc = "Giỏi"
        elif sv._diemTB >= 6.5:
            sv._hocLuc = "Khá"
        elif sv._diemTB >= 5:
            sv._hocLuc = "Trung Bình"
        else:
            sv._hocLuc = "Yếu"

    def showSinhVien(self, listSV):
        print("{:<8} {:<18} {:<8} {:<8} {:<8} {:<8}".format(
            "ID", "Name", "Sex", "Major", "Diem TB", "Hoc Luc"))
        if len(listSV) > 0:
            for sv in listSV:
                print("{:<8} {:<18} {:<8} {:<8} {:<8} {:<8}".format(
                    sv._id, sv._name, sv._sex, sv._major, sv._diemTB, sv._hocLuc))
        print("\n")

    def getListSinhVien(self):
        return self.listSinhVien