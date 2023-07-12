from rest_framework import serializers
from .models import Question, Answer


class AnswerSerializer(serializers.ModelSerializer):
    class Meta:
        model = Answer
        exclude = ('id', 'user',)
        write_only_fields = ('answer_text', 'answer_choice', 
                            'is_correct', 'question',)


class QuestionSerializer(serializers.ModelSerializer):
    answers = AnswerSerializer(many=True, read_only=True)
    answer_choice = serializers.CharField(write_only=True)


    class Meta:
        model = Question
        exclude = ('id', 'user', 'created_at')
        write_only_fields = ('question_text', 'answers',)


class QuestionSubSerializer(QuestionSerializer):
    answers = AnswerSerializer(many=True, read_only=True)
    question = serializers.CharField(write_only=True)
    
    class Meta:
        model = Question
        exclude = ('id', 'user', 'created_at', 'question_text',)
