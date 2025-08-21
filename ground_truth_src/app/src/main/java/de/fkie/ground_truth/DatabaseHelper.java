package de.fkie.ground_truth;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;

public class DatabaseHelper extends SQLiteOpenHelper {

    private static final String DATABASE_NAME = "GroundTruth.db";
    private static final String TABLE_NAME = "grount_truth_table";
    private static final String COL_1 = "ID";
    private static final String COL_2 = "VALUE";

    public DatabaseHelper(Context context) {
        super(context, DATABASE_NAME, null, 1);
    }

    @Override
    public void onCreate(SQLiteDatabase db) {
        db.execSQL("CREATE TABLE " + TABLE_NAME + " (ID INTEGER PRIMARY KEY AUTOINCREMENT, VALUE TEXT)");
    }

    @Override
    public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
        db.execSQL("DROP TABLE IF EXISTS "+TABLE_NAME);
        onCreate(db);
    }

    @Override
    public void onOpen(SQLiteDatabase db){
        super.onOpen(db);
        db.enableWriteAheadLogging();
    }

    public boolean insertData(String name) {
        SQLiteDatabase db = this.getWritableDatabase();
        db.beginTransaction();
        long result = -1;
        try {
            ContentValues contentValues = new ContentValues();
            contentValues.put(COL_2, name);
            result = db.insert(TABLE_NAME, null, contentValues);
            db.setTransactionSuccessful();
        } finally {
            db.endTransaction();
        }
        return result != -1;  // if result == -1 data is not inserted
    }

    public boolean deleteData(String id) {
        SQLiteDatabase db = this.getWritableDatabase();
        return db.delete(TABLE_NAME, "ID = ?", new String[] { id }) > 0;
    }

    public boolean updateData(String id, String name) {
        SQLiteDatabase db = this.getWritableDatabase();
        ContentValues contentValues = new ContentValues();
        contentValues.put(COL_1, id);
        contentValues.put(COL_2, name);
        db.update(TABLE_NAME, contentValues, "ID = ?", new String[] { id });
        return true;
    }

    public Cursor checkForId(String id) {
        SQLiteDatabase db = this.getWritableDatabase();
        return db.rawQuery("SELECT * FROM " + TABLE_NAME + " WHERE ID = ?", new String[] { id });
    }

    public boolean doesIdExist(String id) {
        SQLiteDatabase db = this.getReadableDatabase();
        Cursor res = db.rawQuery("SELECT * FROM " + TABLE_NAME + " WHERE ID = ?", new String[] { id });
        boolean exists = (res.getCount() > 0);
        res.close();
        return exists;
    }
}